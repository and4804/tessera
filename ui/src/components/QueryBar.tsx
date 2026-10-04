import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { api } from "@/api/client";
import { useQueryFields } from "@/api/hooks";
import { applyCompletion, parseQuery, suggest, type Completion } from "@/lib/query-dsl";
import { cx } from "@/lib/format";
import { Icon } from "./ui/Icon";

interface Props {
  value: string;
  onChange: (v: string) => void;
  onSubmit: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
}

/** Field-DSL query bar: live token validation (client parser) + autocomplete (fields, enums, server value hints). */
export function QueryBar({ value, onChange, onSubmit, placeholder, autoFocus }: Props) {
  const fields = useQueryFields();
  const input = useRef<HTMLInputElement>(null);
  const [caret, setCaret] = useState(0);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);

  const parsed = useMemo(() => parseQuery(value, fields), [value, fields]);
  const sug = useMemo(() => suggest(value, caret, fields), [value, caret, fields]);

  // value hints from the API for the field being completed (best-effort; silent if unsupported)
  const vf = sug.ctx.kind === "value" ? sug.ctx.field : undefined;
  const vp = sug.ctx.prefix;
  const hinted = useQuery({
    queryKey: ["field-values", vf, vp],
    queryFn: () => api.fieldValues(vf!, vp),
    enabled: !!vf && fields.some((f) => f.name === vf && (f.suggest ?? f.type === "string")),
    staleTime: 30_000, retry: false
  });
  const items: Completion[] = useMemo(
    () => (hinted.data?.values?.length ? suggest(value, caret, fields, hinted.data.values).items : sug.items),
    [hinted.data, sug.items, value, caret, fields]
  );

  useEffect(() => setActive(0), [items.length, sug.ctx.start]);

  const errors = parsed.issues.filter((i) => i.level === "error");
  const warns = parsed.issues.filter((i) => i.level === "warning");

  const accept = (c: Completion) => {
    const out = applyCompletion(value, sug.ctx, c);
    onChange(out.text);
    requestAnimationFrame(() => {
      input.current?.setSelectionRange(out.caret, out.caret);
      setCaret(out.caret);
      input.current?.focus();
    });
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (open && items.length) {
      if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % items.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + items.length) % items.length); return; }
      if (e.key === "Tab" || (e.key === "Enter" && items[active] && sug.ctx.prefix !== "" && sug.ctx.kind !== "none")) {
        e.preventDefault(); accept(items[active]); return;
      }
    }
    if (e.key === "Escape") setOpen(false);
    if (e.key === "Enter") { setOpen(false); if (!errors.length) onSubmit(value); }
  };

  // token colouring layer rendered under a transparent-text input
  const layer = useMemo(() => {
    const out: JSX.Element[] = [];
    let at = 0;
    const push = (to: number, cls: string, key: string) => {
      if (to > at) out.push(<span key={key + at} className={cls}>{value.slice(at, to)}</span>);
      at = Math.max(at, to);
    };
    for (const t of parsed.terms) {
      push(t.start, "", "ws");
      const bad = parsed.issues.some((i) => i.level === "error" && i.start >= t.start && i.start < t.end);
      if (t.kind === "field") {
        const fs = t.start + (t.negated ? 1 : 0);
        push(fs, "text-unparsed", "neg");
        push(t.fieldEnd!, bad ? "text-unparsed underline decoration-wavy decoration-unparsed/70" : "text-signal", "f");
        push(t.fieldEnd! + 1, "text-ink-3", "c");
        push(t.end, bad ? "text-unparsed" : "text-info", "v");
      } else push(t.end, "text-ink", "t");
    }
    push(value.length, "", "tail");
    return out;
  }, [parsed, value]);

  return (
    <div className="relative">
      <div className={cx("relative flex items-center h-10 rounded-[6px] border bg-well transition-colors",
        errors.length ? "border-unparsed/60" : "border-line-strong focus-within:border-signal/80 focus-within:shadow-[0_0_0_3px_rgb(var(--signal)/0.12)]")}>
        <Icon name="search" size={15} className="ml-3 text-ink-3 shrink-0" />
        <div className="relative flex-1 h-full mx-2.5">
          <div aria-hidden className="absolute inset-0 flex items-center whitespace-pre mono text-[13px] overflow-hidden pointer-events-none">{layer}</div>
          <input ref={input} value={value} autoFocus={autoFocus} spellCheck={false} autoComplete="off" aria-label="Query"
            aria-invalid={errors.length > 0} aria-autocomplete="list" aria-expanded={open && items.length > 0}
            placeholder={placeholder ?? 'src_ip:10.1.1.15 action:denied dst_port:22 "free text"'}
            className="absolute inset-0 w-full h-full bg-transparent mono text-[13px] outline-none text-transparent caret-[rgb(var(--signal))] placeholder:text-ink-3"
            onChange={(e) => { onChange(e.target.value); setCaret(e.target.selectionStart ?? e.target.value.length); setOpen(true); }}
            onKeyDown={onKey}
            onKeyUp={(e) => setCaret((e.target as HTMLInputElement).selectionStart ?? 0)}
            onClick={(e) => setCaret((e.target as HTMLInputElement).selectionStart ?? 0)}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 120)} />
        </div>
        {value && <button className="btn btn-ghost btn-sm mr-1 !px-1.5" aria-label="Clear query" onClick={() => { onChange(""); onSubmit(""); input.current?.focus(); }}><Icon name="x" size={13} /></button>}
        <button className="btn btn-primary mr-1.5 !h-7" onClick={() => !errors.length && onSubmit(value)} disabled={errors.length > 0}>Run <kbd className="mono text-[10px] opacity-60">↵</kbd></button>
      </div>

      {open && items.length > 0 && (
        <ul role="listbox" className="absolute z-30 mt-1.5 w-[min(560px,100%)] panel !bg-raised overflow-hidden shadow-[0_24px_60px_-12px_rgba(0,0,0,.8)] animate-rise">
          {items.map((c, i) => (
            <li key={c.kind + c.label} role="option" aria-selected={i === active}
              onMouseDown={(e) => { e.preventDefault(); accept(c); }} onMouseEnter={() => setActive(i)}
              className={cx("flex items-center gap-3 px-3 h-8 cursor-pointer", i === active && "bg-signal/10")}>
              <span className={cx("mono text-[12.5px]", c.kind === "field" ? "text-signal" : "text-info")}>{c.label}</span>
              <span className="text-ink-3 text-[11.5px] truncate">{c.detail}</span>
              {i === active && <kbd className="ml-auto mono text-[10px] text-ink-3 border border-line-strong rounded px-1">tab</kbd>}
            </li>
          ))}
        </ul>
      )}
      {(errors.length > 0 || warns.length > 0) && (
        <div className="mt-1.5 flex flex-col gap-0.5 mono text-[11.5px]" role="status">
          {errors.slice(0, 3).map((i, k) => <span key={k} className="text-unparsed">✗ {i.message}</span>)}
          {errors.length === 0 && warns.slice(0, 2).map((i, k) => <span key={k} className="text-partial">! {i.message}</span>)}
        </div>
      )}
    </div>
  );
}
