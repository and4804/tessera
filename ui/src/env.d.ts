/// <reference types="vite/client" />
declare module "monaco-editor/esm/vs/basic-languages/yaml/yaml.contribution";
declare module "monaco-editor/esm/vs/editor/editor.worker?worker" {
  const W: new () => Worker;
  export default W;
}
