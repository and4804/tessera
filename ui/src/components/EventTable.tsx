import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useLayoutEffect, useMemo, useRef, type ReactNode } from "react";
import type { EventRow, TailRow } from "@/api/types";
import { actionName, className as clsName, cx, endpoint, fmtClock, fmtCompact, fmtDate } from "@/lib/format";
import { SourceBadge, StatusChip } from "./ui/primitives";

type Row = EventRow | TailRow;
const col = createColumnHelper<Row>();

export const ROW_H = 30;
const detailOf = (r: Row) => r.signature ?? r.url ?? r.dns_query ?? r.user_name ?? ("message" in r ? (r as TailRow).message : null) ?? "";

const WIDTHS: Record<string, string> = {
  time: "96px", source: "170px", status: "92px", class: "128px", src: "172px", dst: "172px",
  proto: "52px", action: "72px", bytes: "104px", detail: "minmax(180px,1fr)", cov: "46px"
};

function buildColumns(withDate: boolean, withMs: boolean) {
  return [
    col.accessor("time", {
      id: "time", header: "Time (UTC)", 
      cell: (c) => (
        <span className="mono num text-ink-2 whitespace-nowrap">
          {withDate && <span className="text-ink-3">{fmtDate(c.getValue())} </span>}{fmtClock(c.getValue(), withMs)}
        </span>
      )
    }),
    col.accessor("source_id", { id: "source", header: "Source", cell: (c) => <SourceBadge id={c.getValue()} /> }),
    col.accessor("status", { id: "status", header: "Status", cell: (c) => <StatusChip status={c.getValue()} /> }),
    col.accessor("class_uid", { id: "class", header: "Class", cell: (c) => <span className="text-ink-2 truncate">{clsName(c.getValue())}</span> }),
    col.display({ id: "src", header: "Source addr", cell: (c) => <span className="mono num text-ink">{endpoint(c.row.original.src_ip, c.row.original.src_port)}</span> }),
    col.display({ id: "dst", header: "Destination", cell: (c) => <span className="mono num text-ink">{endpoint(c.row.original.dst_ip, c.row.original.dst_port)}</span> }),
    col.accessor("proto_name", { id: "proto", header: "Proto", cell: (c) => <span className="mono text-ink-2 uppercase">{c.getValue() ?? "—"}</span> }),
    col.accessor("action_id", {
      id: "action", header: "Action",
      cell: (c) => {
        const v = c.getValue();
        return <span className={cx("text-[12px]", v === 1 ? "text-parsed" : v === 2 ? "text-unparsed" : "text-ink-3")}>{actionName(v)}</span>;
      }
    }),
    col.display({
      id: "bytes", header: "In / Out",
      cell: (c) => <span className="mono num text-ink-2">{c.row.original.bytes_in == null && c.row.original.bytes_out == null ? "—" : `${fmtCompact(c.row.original.bytes_in)} / ${fmtCompact(c.row.original.bytes_out)}`}</span>
    }),
    col.display({ id: "detail", header: "Detail", cell: (c) => <span className="text-ink-2 truncate" title={detailOf(c.row.original)}>{detailOf(c.row.original)}</span> }),
    col.accessor("coverage", {
      id: "cov", header: "Cov",
      cell: (c) => {
        const v = c.getValue();
        return <span className={cx("mono num text-[11px]", v >= 0.85 ? "text-parsed" : v >= 0.5 ? "text-partial" : "text-unparsed")}>{Math.round(v * 100)}</span>;
      }
    })
  ];
}

interface Props {
  rows: readonly Row[];
  onOpen: (r: Row) => void;
  empty?: ReactNode;
  withDate?: boolean;
  withMs?: boolean;
  /** Number of rows just inserted at the top (keeps the viewport stable when scrolled down). */
  prepended?: number;
  /** Highlight this many newest rows with a flash. */
  fresh?: number;
  onEnd?: () => void;
  footer?: ReactNode;
  className?: string;
}

export function EventTable({ rows, onOpen, empty, withDate, withMs = true, prepended = 0, fresh = 0, onEnd, footer, className }: Props) {
  const columns = useMemo(() => buildColumns(!!withDate, withMs), [withDate, withMs]);
  const data = useMemo(() => rows as Row[], [rows]);
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel(), getRowId: (r) => r.event_id });
  const model = table.getRowModel().rows;
  const scroller = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({ count: model.length, getScrollElement: () => scroller.current, estimateSize: () => ROW_H, overscan: 14 });

  const widths = columns.map((c) => (c.id === "time" && withDate ? "188px" : WIDTHS[c.id as string])).join(" ");
  const minW = 1340;

  useLayoutEffect(() => {
    const el = scroller.current;
    if (el && prepended > 0 && el.scrollTop > 8) el.scrollTop += prepended * ROW_H;
  }, [prepended, rows]);

  const items = virt.getVirtualItems();
  const lastIdx = items.length ? items[items.length - 1].index : -1;
  useEffect(() => {
    if (onEnd && lastIdx >= 0 && lastIdx >= model.length - 8) onEnd();
  }, [lastIdx, model.length, onEnd]);

  return (
    <div className={cx("flex flex-col min-h-0", className)}>
      <div ref={scroller} className="flex-1 min-h-0 overflow-auto relative" role="table" aria-rowcount={model.length}>
        <div style={{ minWidth: minW }}>
          <div role="row" className="grid-cols-events sticky top-0 z-10 h-8 px-4 bg-panel/95 backdrop-blur border-b border-line kicker !text-[10px]" style={{ gridTemplateColumns: widths }}>
            {table.getHeaderGroups()[0].headers.map((h) => (
              <div key={h.id} role="columnheader" className="truncate">{flexRender(h.column.columnDef.header, h.getContext())}</div>
            ))}
          </div>
          {model.length === 0 ? (
            empty
          ) : (
            <div style={{ height: virt.getTotalSize(), position: "relative" }}>
              {items.map((v) => {
                const r = model[v.index];
                return (
                  <div key={r.id} role="row" tabIndex={0} data-index={v.index}
                    onClick={() => onOpen(r.original)}
                    onKeyDown={(e) => { if (e.key === "Enter") onOpen(r.original); }}
                    className={cx("grid-cols-events absolute left-0 right-0 px-4 cursor-pointer border-b border-line/50 text-[12.5px] hover:bg-raised/80 focus-visible:bg-raised",
                      v.index < fresh && "animate-flash")}
                    style={{ gridTemplateColumns: widths, height: ROW_H, transform: `translateY(${v.start}px)` }}>
                    {r.getVisibleCells().map((c) => (
                      <div key={c.id} role="cell" className="min-w-0 flex items-center">{flexRender(c.column.columnDef.cell, c.getContext())}</div>
                    ))}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
      {footer}
    </div>
  );
}
