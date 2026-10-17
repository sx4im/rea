import { describe, expect, it } from "vitest";

import type { ArtifactInventorySnapshot } from "../../domain/artifactInventorySnapshot.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { analyzeJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import type {
  AnalyzedJavaScriptArtifactFile,
  JavaScriptModuleArtifactAnalysis,
} from "./JavaScriptArtifactAnalysisTypes.js";
import { javascriptArtifactAnalysisScopes } from "./JavaScriptArtifactAnalysisTypes.js";
import { JavaScriptArtifactGraphAccumulator } from "./JavaScriptArtifactGraphAccumulator.js";
import type { JavaScriptArtifactGraphContext } from "./JavaScriptArtifactGraphContext.js";
import {
  addJavaScriptArtifactFiles,
  createJavaScriptArtifactRootNode,
} from "./JavaScriptArtifactGraphStructure.js";

const SHA256 = "a".repeat(64);
const REASON =
  "main.js: Resource constraint during analyze_javascript_application: Owned JavaScript worker exhausted its heap while analyzing main.js during static";

const skippedFile = (): JavaScriptArtifactFile => ({
  path: "main.js",
  container_sha256: SHA256,
  sha256: SHA256,
  bytes: 5000107,
  inventory_artifact_id: `art_${SHA256}`,
  kind: "javascript",
  unpacked: false,
  text: { included: true, value: "const {ipcMain}=require('electron');\n" },
});

const skippedEntry = (
  file: JavaScriptArtifactFile,
): AnalyzedJavaScriptArtifactFile => ({
  file,
  javascript: null,
  semantic: null,
  analysis_failure: {
    scope: javascriptArtifactAnalysisScopes["javascript"],
    status: "interrupted",
    reason: REASON,
    error: { code: "resource_constraint" },
    limits: null,
  },
});

const analysisFor = (
  entries: readonly AnalyzedJavaScriptArtifactFile[],
): JavaScriptModuleArtifactAnalysis => ({
  files: entries,
  packages: [],
  json_modules: [],
  html_scripts: [],
  html_inline_scripts: [],
  source_maps: [],
  visited_ast_nodes: 0,
  findings: 0,
  modules: 0,
  parse_failures: 0,
  limitations: [],
});

const contextFor = (
  file: JavaScriptArtifactFile,
  analysis: JavaScriptModuleArtifactAnalysis,
): JavaScriptArtifactGraphContext => {
  const accumulator = new JavaScriptArtifactGraphAccumulator();
  const snapshot = {
    manifest: {
      root_artifact_id: `art_${SHA256}`,
      root_sha256: SHA256,
      root_format: "directory",
      manifest_id: `agm_${SHA256}`,
      graph_sha256: SHA256,
    },
    nodes: [{ artifact_id: `art_${SHA256}`, sha256: SHA256, size: 1 }],
  } as unknown as ArtifactInventorySnapshot;
  const fileSet = {
    files: [file],
    unavailable_relevant_files: [],
    containers: [],
    text_bytes_read: file.bytes,
    invalid_utf8_files: 0,
  };
  return {
    accumulator,
    snapshot,
    fileSet,
    analysis,
    directoryPaths: new Set<string>(),
    root: createJavaScriptArtifactRootNode(accumulator, snapshot),
    filesByPath: new Map([[file.path, file]]),
    unanalyzedFiles: undefined,
    fileNodes: new Map(),
    assetNodes: new Map(),
    sourceModuleNodes: new Map(),
    chunkNodes: new Map(),
    moduleNodes: new Map(),
    containerNodes: new Map(),
  };
};

const fileObservation = (context: JavaScriptArtifactGraphContext) => {
  const node = context.accumulator
    .nodes()
    .find(({ kind }) => kind === "javascript-asset");
  if (node === undefined) throw new Error("Expected a javascript-asset node");
  const observation = node.observations[0];
  if (observation === undefined) throw new Error("Expected a file observation");
  return observation.properties;
};

describe("skipped JavaScript parse reporting", () => {
  it("marks parse_status skipped for a JavaScript file whose worker analysis failed", () => {
    const file = skippedFile();
    const context = contextFor(file, analysisFor([skippedEntry(file)]));
    addJavaScriptArtifactFiles(context);
    expect(fileObservation(context).parse_status).toBe("skipped");
  });

  it("keeps parse_status null for a JavaScript file never attempted", () => {
    const file = skippedFile();
    const entry: AnalyzedJavaScriptArtifactFile = {
      file,
      javascript: null,
      semantic: null,
    };
    const context = contextFor(file, analysisFor([entry]));
    addJavaScriptArtifactFiles(context);
    expect(fileObservation(context).parse_status).toBeNull();
  });

  it("keeps the parsed status for an analyzed JavaScript file", () => {
    const file = skippedFile();
    const javascript = analyzeJavaScriptStaticSource(
      "const {ipcMain}=require('electron');\n",
    );
    const entry: AnalyzedJavaScriptArtifactFile = {
      file,
      javascript,
      semantic: null,
    };
    const context = contextFor(file, analysisFor([entry]));
    addJavaScriptArtifactFiles(context);
    expect(fileObservation(context).parse_status).toBe(javascript.parse_status);
  });
});
