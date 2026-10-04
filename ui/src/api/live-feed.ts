import { RingBuffer } from "@/lib/ring";
import { streamUrl } from "./client";
import type { EventStatus, StreamMessage, StreamRequest, TailRow } from "./types";

export const LIVE_CAP = 5000; // §7.14: ring buffer cap

export type FeedStatus = "connecting" | "open" | "retrying";
export interface FeedSnapshot {
  version: number;
  status: FeedStatus;
  attempt: number;
  size: number;
  total: number; // rows received since connect
  evicted: number;
  eps: number; // measured over the last few seconds from real arrivals
  epsSeries: number[]; // last 60 one-second bins (oldest first)
  serverDropped: number;
  error: string | null;
  buffer: RingBuffer<TailRow>;
}

/**
 * Framework-free WebSocket tail. Batches arrive at server cadence; we push them into a ring
 * buffer immediately and notify React at most every `notifyMs` so a 10k eps stream never
 * triggers 10k renders.
 */
export class LiveFeed {
  private ws: WebSocket | null = null;
  private buffer = new RingBuffer<TailRow>(LIVE_CAP);
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private tick: ReturnType<typeof setInterval> | null = null;
  private closed = false;
  private attempt = 0;
  private version = 0;
  private status: FeedStatus = "connecting";
  private error: string | null = null;
  private serverDropped = 0;
  private bins: number[] = new Array(60).fill(0);
  private binSecond = Math.floor(Date.now() / 1000);
  private dirty = false;
  private filter: StreamRequest = { op: "filter", q: "", sources: [], statuses: [] };
  private snap!: FeedSnapshot;

  constructor(private notifyMs = 200) {
    this.rebuild();
  }

  start() {
    this.closed = false;
    this.connect();
    this.tick = setInterval(() => {
      this.rotateBins(Date.now());
      this.dirty = true;
      this.flush();
    }, 1000);
  }
  stop() {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.flushTimer) { clearTimeout(this.flushTimer); this.flushTimer = null; }
    if (this.tick) clearInterval(this.tick);
    const w = this.ws;
    this.ws = null; // detach first so the stale socket's close event is ignored
    w?.close();
  }

  setFilter(q: string, sources: string[], statuses: EventStatus[]) {
    this.filter = { op: "filter", q, sources, statuses };
    this.send();
  }
  clear() {
    this.buffer.clear();
    this.buffer.total = 0;
    this.buffer.evicted = 0;
    this.dirty = true;
    this.flush();
  }

  subscribe = (cb: () => void) => {
    this.listeners.add(cb);
    return () => void this.listeners.delete(cb);
  };
  getSnapshot = () => this.snap;

  private send() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(this.filter));
  }

  private connect() {
    if (this.closed) return;
    this.status = this.attempt === 0 ? "connecting" : "retrying";
    this.dirty = true;
    this.flush();
    let ws: WebSocket;
    try {
      ws = new WebSocket(streamUrl());
    } catch (e) {
      this.error = (e as Error).message;
      this.scheduleRetry();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      if (this.ws !== ws) return;
      this.attempt = 0;
      this.status = "open";
      this.error = null;
      this.send();
      this.dirty = true;
      this.flush();
    };
    ws.onmessage = (ev) => {
      if (this.ws !== ws) return;
      let m: StreamMessage;
      try {
        m = JSON.parse(ev.data as string) as StreamMessage;
      } catch {
        return;
      }
      if (m.type === "batch") {
        if (m.events.length) {
          this.buffer.push(m.events);
          this.rotateBins(Date.now());
          this.bins[59] += m.events.length;
        }
        if (m.dropped) this.serverDropped += m.dropped;
        this.dirty = true;
        this.scheduleFlush();
      } else if (m.type === "error") {
        this.error = m.message;
        this.dirty = true;
        this.scheduleFlush();
      }
    };
    ws.onerror = () => {
      this.error = "WebSocket error";
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      if (!this.closed) this.scheduleRetry();
    };
  }

  private scheduleRetry() {
    this.attempt++;
    this.status = "retrying";
    this.dirty = true;
    this.flush();
    const delay = Math.min(8000, 400 * 2 ** Math.min(this.attempt, 5));
    this.timer = setTimeout(() => this.connect(), delay);
  }

  private rotateBins(nowMs: number) {
    const s = Math.floor(nowMs / 1000);
    const gap = Math.min(60, s - this.binSecond);
    if (gap > 0) {
      for (let i = 0; i < gap; i++) {
        this.bins.shift();
        this.bins.push(0);
      }
      this.binSecond = s;
    }
  }

  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private scheduleFlush() {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush();
    }, this.notifyMs);
  }
  private flush() {
    if (!this.dirty) return;
    this.dirty = false;
    this.rebuild();
    this.listeners.forEach((l) => l());
  }
  private rebuild() {
    // eps = mean over the last 5 COMPLETED seconds (current partial second excluded)
    const last = this.bins.slice(54, 59);
    const eps = last.reduce((a, b) => a + b, 0) / last.length;
    this.version++;
    this.snap = {
      version: this.version,
      status: this.status,
      attempt: this.attempt,
      size: this.buffer.size,
      total: this.buffer.total,
      evicted: this.buffer.evicted,
      eps,
      epsSeries: this.bins.slice(),
      serverDropped: this.serverDropped,
      error: this.error,
      buffer: this.buffer
    };
  }
}
