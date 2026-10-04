/**
 * Monaco, fully bundled (R5). We drive the local ESM build directly (no `@monaco-editor/react`, whose
 * loader embeds a CDN default URL); the editor worker is a Vite
 * `?worker` chunk. Only the YAML tokenizer is pulled in (no language services => no extra workers).
 */
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import "monaco-editor/esm/vs/basic-languages/yaml/yaml.contribution";
import EditorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

(self as unknown as { MonacoEnvironment: unknown }).MonacoEnvironment = {
  getWorker: () => new EditorWorker()
};

monaco.editor.defineTheme("tessera", {
  base: "vs-dark",
  inherit: true,
  rules: [
    { token: "comment", foreground: "6c7688", fontStyle: "italic" },
    { token: "type", foreground: "d4ff3a" },
    { token: "string", foreground: "6ea8ff" },
    { token: "number", foreground: "f5a524" },
    { token: "keyword", foreground: "35d6b0" },
    { token: "operators", foreground: "959fb1" }
  ],
  colors: {
    "editor.background": "#05070a",
    "editor.foreground": "#e2e7f0",
    "editorLineNumber.foreground": "#3a4357",
    "editorLineNumber.activeForeground": "#959fb1",
    "editor.lineHighlightBackground": "#0d1016",
    "editor.selectionBackground": "#d4ff3a30",
    "editorCursor.foreground": "#d4ff3a",
    "editorIndentGuide.background1": "#1e242f",
    "editorGutter.background": "#05070a",
    "scrollbarSlider.background": "#30384880"
  }
});

export { monaco };
