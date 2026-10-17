import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { applicationVersionComparisonResultSchema } from "../../../src/domain/javascript/javascriptApplicationVersionComparisonSchemas.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "uses syntax-aware bundle fingerprints for changed syntax and renamed bindings",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-fingerprint-version-");
    const pairs = [
      ["bigint", "exports.v = 1n;", "exports.v = 2n;"],
      ["bigint-key", "exports.v = { 1n: 1 };", "exports.v = { 2n: 1 };"],
      ["directive", '"use strict";', '"use asm";'],
      ["assignment", "exports.v = 1;", "exports.v += 1;"],
      ["string", 'exports.v = "left";', 'exports.v = "right";'],
      ["class-method", "class A { foo() {} }", "class A { bar() {} }"],
      ["class-field", "class A { foo = 1; }", "class A { bar = 1; }"],
      [
        "rename",
        "const key = selectKey(); exports.read = value[key];",
        "const selector = selectKey(); exports.read = value[selector];",
      ],
      [
        "rename-class-method",
        "const key = selectKey(); class A { [key]() {} }",
        "const selector = selectKey(); class B { [selector]() {} }",
      ],
      [
        "rename-class-field",
        "const key = selectKey(); class A { [key] = 1; }",
        "const selector = selectKey(); class B { [selector] = 1; }",
      ],
    ] as const;
    const versions = [];
    for (const side of [1, 2] as const) {
      const application = join(root, String(side));
      await mkdir(application);
      for (const [name, left, right] of pairs)
        await writeFile(
          join(application, `${name}.js`),
          `globalThis.webpackChunkApp.push([[1], {17(module, exports) {${side === 1 ? left : right}}}]);`,
        );
      const response = await cli.run({
        arguments: ["analyze-javascript-application", application, "--json"],
        environment: { REA_LOG_LEVEL: "silent" },
      });
      expect(response.exitCode, response.stderr).toBe(0);
      versions.push(parseEvidence(response.json));
    }
    const [left, right] = versions;
    if (left === undefined || right === undefined)
      throw new Error("Missing bundle version Evidence");
    const analyses = versions.map(({ normalized_result }) =>
      javascriptApplicationAnalysisResultSchema.parse(normalized_result),
    );
    const modules = analyses.map(({ graph }) => {
      expect(graph.coverage.status).toBe("complete");
      return new Map(
        graph.nodes.flatMap((node) =>
          node.observations.flatMap(({ properties, evidence }) =>
            typeof properties.structural_fingerprint_sha256 === "string"
              ? [[properties.path, { node, properties, evidence }] as const]
              : [],
          ),
        ),
      );
    });
    const inputPath = join(root, "comparison.json");
    await writeFile(inputPath, JSON.stringify({ left, right }));
    const response = await cli.run({
      arguments: ["compare-application-versions", inputPath, "--json"],
      environment: { REA_LOG_LEVEL: "silent" },
    });
    expect(response.exitCode, response.stderr).toBe(0);
    const result = applicationVersionComparisonResultSchema.parse(
      parseEvidence(response.json).normalized_result,
    );
    expect(result.coverage.status).toBe("complete-within-inputs");
    for (const [name] of pairs) {
      const isRename = name.startsWith("rename");
      const a = modules[0]?.get(`${name}.js`);
      const b = modules[1]?.get(`${name}.js`);
      if (a === undefined || b === undefined)
        throw new Error(`Missing ${name} bundle module`);
      expect(a.evidence.coverage.status).toBe("complete");
      expect(b.evidence.coverage.status).toBe("complete");
      expect(a.properties.structural_fingerprint_algorithm).toBe(
        "babel-ast-v3",
      );
      expect(b.properties.structural_fingerprint_algorithm).toBe(
        "babel-ast-v3",
      );
      expect(a.properties.source_sha256).not.toBe(b.properties.source_sha256);
      expect(
        a.properties.structural_fingerprint_sha256 ===
          b.properties.structural_fingerprint_sha256,
        name,
      ).toBe(isRename);
      const item = result.items.find(
        ({ left_node_id }) => left_node_id === a.node.node_id,
      );
      expect(item).toMatchObject(
        isRename
          ? {
              right_node_id: b.node.node_id,
              status: "changed",
              match: {
                status: "matched",
                basis: "structural-fingerprint",
                confidence: "medium",
              },
            }
          : {
              right_node_id: null,
              status: "removed",
              match: { status: "unmatched" },
            },
      );
      if (!isRename)
        expect(
          result.items.find(
            ({ right_node_id }) => right_node_id === b.node.node_id,
          ),
        ).toMatchObject({
          left_node_id: null,
          status: "added",
          match: { status: "unmatched" },
        });
      const asset = analyses[0]?.graph.nodes.find(
        ({ kind, observations }) =>
          kind === "javascript-asset" &&
          observations.some(
            ({ properties }) => properties.path === `${name}.js`,
          ),
      );
      expect(asset).toBeDefined();
      expect(
        result.items.find(
          ({ left_node_id }) => left_node_id === asset?.node_id,
        ),
      ).toMatchObject({
        status: "changed",
        dimensions: expect.arrayContaining(["content"]),
        match: { status: "matched", basis: "semantic-key" },
      });
    }
    expect(result.matching.structural_fingerprint).toBe(3);
  },
);

cliTest(
  "pairs repeated factory bodies by identity when application versions retain a shared bundle",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-version-matching-");
    const factoryCount = 32;
    const factories = Array.from(
      { length: factoryCount },
      (_, index) => `${index}: function() {}`,
    ).join(",");
    const bundle = `globalThis.webpackChunkApp.push([[1], {${factories}}]);`;
    const versions = await Promise.all(
      [1, 2].map(async (version) => {
        const application = join(root, String(version));
        await mkdir(application);
        await writeFile(
          join(application, "package.json"),
          JSON.stringify({ name: "shared-bundle", version: `${version}.0.0` }),
        );
        await writeFile(join(application, "chunk.js"), bundle);
        const response = await cli.run({
          arguments: ["analyze-javascript-application", application, "--json"],
          environment: { REA_LOG_LEVEL: "silent" },
        });
        expect(response.exitCode, response.stderr).toBe(0);
        return parseEvidence(response.json);
      }),
    );
    const [left, right] = versions;
    if (left === undefined || right === undefined)
      throw new Error("Missing application version Evidence");
    const analyses = versions.map(({ normalized_result }) =>
      javascriptApplicationAnalysisResultSchema.parse(normalized_result),
    );
    const factoryNodes = analyses.map(({ graph }) => {
      expect(graph.coverage.status).toBe("complete");
      const nodes = graph.nodes.filter(
        ({ kind, observations }) =>
          kind === "javascript-module" &&
          observations.some(
            ({ properties }) => properties.module_key !== undefined,
          ),
      );
      expect(nodes).toHaveLength(factoryCount);
      const sourceDigests = nodes.flatMap(({ observations }) =>
        observations.map(({ properties }) => properties.source_sha256),
      );
      expect(sourceDigests.every((digest) => typeof digest === "string")).toBe(
        true,
      );
      expect(new Set(sourceDigests).size).toBe(1);
      return nodes;
    });
    const inputPath = join(root, "comparison.json");
    await writeFile(inputPath, JSON.stringify({ left, right }));
    const response = await cli.run({
      arguments: ["compare-application-versions", inputPath, "--json"],
      environment: { REA_LOG_LEVEL: "silent" },
    });
    expect(response.exitCode, response.stderr).toBe(0);
    const result = applicationVersionComparisonResultSchema.parse(
      parseEvidence(response.json).normalized_result,
    );

    expect(result.left.root_artifact_sha256).not.toBe(
      result.right.root_artifact_sha256,
    );
    expect(result.matching.ambiguous).toBe(0);
    expect(result.coverage.status).toBe("complete-within-inputs");
    expect(factoryNodes[0]?.map(({ node_id }) => node_id)).toEqual(
      factoryNodes[1]?.map(({ node_id }) => node_id),
    );
    for (const node of factoryNodes[0] ?? []) {
      expect(
        result.items.find(({ left_node_id }) => left_node_id === node.node_id),
      ).toMatchObject({
        status: "unchanged",
        right_node_id: node.node_id,
        match: {
          status: "matched",
          basis: "exact-node-identity",
          candidate_left_node_ids: [],
          candidate_right_node_ids: [],
        },
      });
    }
  },
);

cliTest(
  "retains exact source-module pairing while a changed sibling's identity is unresolved",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-source-module-version-");
    const versions = await Promise.all(
      ["left", "right"].map(async (name) => {
        const application = join(root, name);
        await mkdir(join(application, "src"), { recursive: true });
        await writeFile(
          join(application, "package.json"),
          JSON.stringify({
            name: "source-module-fixture",
            version: "1.0.0",
            main: "src/main.js",
          }),
        );
        await writeFile(
          join(application, "src/main.js"),
          'require("./util.js");\n',
        );
        await writeFile(
          join(application, "src/util.js"),
          `module.exports = ${JSON.stringify(name)};\n`,
        );
        const response = await cli.run({
          arguments: ["analyze-javascript-application", application, "--json"],
          environment: { REA_LOG_LEVEL: "silent" },
        });
        expect(response.exitCode, response.stderr).toBe(0);
        return parseEvidence(response.json);
      }),
    );
    const [left, right] = versions;
    if (left === undefined || right === undefined)
      throw new Error("Missing source module Evidence");
    const analyses = versions.map(({ normalized_result }) =>
      javascriptApplicationAnalysisResultSchema.parse(normalized_result),
    );
    const sourceModules = analyses.map(({ graph }) => {
      const node = graph.nodes.find(
        ({ kind, observations }) =>
          kind === "javascript-module" &&
          observations.some(
            ({ properties }) =>
              properties.semantic_role === "source-module" &&
              properties.path === "src/main.js",
          ),
      );
      if (node === undefined) throw new Error("Missing main source module");
      expect(
        node.observations.some(
          ({ properties }) => typeof properties.source_sha256 === "string",
        ),
      ).toBe(true);
      return node;
    });
    const inputPath = join(root, "comparison.json");
    await writeFile(inputPath, JSON.stringify({ left, right }));
    const response = await cli.run({
      arguments: ["compare-application-versions", inputPath, "--json"],
      environment: { REA_LOG_LEVEL: "silent" },
    });
    expect(response.exitCode, response.stderr).toBe(0);
    const result = applicationVersionComparisonResultSchema.parse(
      parseEvidence(response.json).normalized_result,
    );

    const item = result.items.find(
      ({ left_node_id }) => left_node_id === sourceModules[0]?.node_id,
    );
    expect(item).toMatchObject({
      left_node_id: sourceModules[0]?.node_id,
      right_node_id: sourceModules[1]?.node_id,
      status: "unknown",
      dimensions: [],
      match: {
        status: "matched",
        basis: "exact-module-source-digest",
        confidence: "exact",
      },
    });
    expect(item?.limitations.join(" ")).toMatch(
      /relationship.*identity.*unresolved/iu,
    );
    expect(result.coverage.status).toBe("complete-within-inputs");
    const mainId = sourceModules[0]?.node_id;
    const neighbors = new Set(
      analyses[0]?.graph.edges.flatMap((edge) =>
        edge.source_node_id === mainId
          ? [edge.target_node_id]
          : edge.target_node_id === mainId
            ? [edge.source_node_id]
            : [],
      ),
    );
    expect(
      result.items.some(
        (other) =>
          other.left_node_id !== null &&
          neighbors.has(other.left_node_id) &&
          other.match.status !== "matched",
      ),
    ).toBe(true);
  },
);
