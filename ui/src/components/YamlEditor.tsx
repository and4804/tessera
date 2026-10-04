import { useEffect, useRef } from "react";
import type { LintIssue } from "@/api/types";
import { monaco } from "@/lib/monaco";

/** Monaco YAML editor (local bundle) with server lint issues surfaced as editor markers. */
export function YamlEditor({ value, onChange, issues, height = 440 }: { value: string; onChange: (v: string) => void; issues: LintIssue[]; height?: number }) {
  const host = useRef<HTMLDivElement>(null);
  const ed = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    const editor = monaco.editor.create(host.current, {
      value, language: "yaml", theme: "rosetta", automaticLayout: true,
      fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: 12.5, lineHeight: 20, minimap: { enabled: false },
      scrollBeyondLastLine: false, tabSize: 2, insertSpaces: true, renderWhitespace: "none", padding: { top: 10, bottom: 10 },
      smoothScrolling: true, cursorBlinking: "smooth", overviewRulerBorder: false, glyphMargin: false, folding: true, wordWrap: "off"
    });
    ed.current = editor;
    const sub = editor.onDidChangeModelContent(() => onChangeRef.current(editor.getValue()));
    return () => { sub.dispose(); editor.getModel()?.dispose(); editor.dispose(); ed.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const e = ed.current;
    if (e && e.getValue() !== value) e.setValue(value);
  }, [value]);

  useEffect(() => {
    const model = ed.current?.getModel();
    if (!model) return;
    monaco.editor.setModelMarkers(model, "ulpf-lint", issues.map((i) => ({
      severity: i.level === "error" ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning,
      message: i.message,
      startLineNumber: i.line ?? 1, startColumn: 1, endLineNumber: i.line ?? 1, endColumn: 400
    })));
  }, [issues]);

  return <div ref={host} style={{ height }} />;
}
