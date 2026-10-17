import { describe, expect, it } from "vitest";
import { connectGhidraMcp, sessionEvidence } from "./ghidraMcpHarness.js";
import {
  fixtureDosOverlapLoadImage,
  compareDosClientFixture,
} from "../../../src/ghidra/GhidraLoadImage.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { nativeLoadImageSchema } from "../../../src/domain/native/nativeLoadImage.js";
import { ok } from "../../../src/domain/result.js";

it.each([
  { state: "final", failed: [] },
  { state: "intermediate", failed: ["relocation_records"] },
  { state: "missing-record", failed: ["relocation_records"] },
  { state: "duplicate-record", failed: ["relocation_records"] },
  { state: "reversed-records", failed: [] },
  { state: "bad-source", failed: ["modified_file_sha256"] },
  { state: "bad-mapping", failed: ["mapping[1].memory_sha256"] },
])(
  "retains final overlapping MZ relocation Evidence through MCP ($state)",
  async ({ state, failed }) => {
    const fixture = fixtureDosOverlapLoadImage();
    const first = fixture.observation.relocations[0];
    const source = fixture.observation.source_files[0];
    const mapping = fixture.observation.mappings[1];
    if (first === undefined || source === undefined || mapping === undefined)
      throw new Error("Missing authored overlap facts");
    if (state === "intermediate") first.memory_bytes_hex = "0410";
    if (state === "missing-record") fixture.observation.relocations.pop();
    if (state === "duplicate-record")
      fixture.observation.relocations.push(structuredClone(first));
    if (state === "reversed-records") fixture.observation.relocations.reverse();
    if (state === "bad-source") source.modified_sha256 = "f".repeat(64);
    if (state === "bad-mapping") mapping.sha256 = "f".repeat(64);
    const directory = await createTestTempDirectory("rea-mcp-mz-overlap-");
    const targetPath = join(directory, "inert.exe");
    await writeFile(targetPath, fixture.bytes);
    const harness = await connectGhidraMcp(
      "ghidra-mz-relocation-windows",
      async () => ok(jsonValueSchema.parse(fixture.observation)),
      {
        targetPath,
        sessionTarget: {
          name: "inert.exe",
          language_id: fixture.observation.language_id,
          compiler_spec_id: fixture.observation.compiler_spec_id,
          image_base: fixture.observation.image_base,
          default_address_space: fixture.observation.default_address_space,
          sha256: fixture.sha256,
        },
        attestDosTargetSnapshot: async (observations) =>
          compareDosClientFixture(fixture.bytes, fixture.sha256, observations),
      },
    );
    try {
      const reply = await harness.mcp.callTool({
        name: "inspect_native_load_image",
        arguments: {},
      });
      expect(reply.isError).not.toBe(true);
      const evidence = sessionEvidence(
        harness.session,
        reply.structuredContent,
      );
      const result = nativeLoadImageSchema.parse(evidence.normalized_result);
      if (result.status === "unsupported")
        throw new Error("Expected MZ comparison");
      expect(result.status).toBe(failed.length > 0 ? "mismatch" : "verified");
      expect(
        result.checks
          .filter((check) => !check.matched)
          .map((check) => check.name),
      ).toEqual(failed);
      expect(result.observations.relocations).toEqual(
        fixture.observation.relocations,
      );
    } finally {
      await harness.close();
    }
  },
);

describe("Ghidra MCP native API evidence", () => {
  it("returns complete native API boundaries without output-cap unknowns", async () => {
    const harness = await connectGhidraMcp("ghidra-native-api");
    const { mcp, session } = harness;
    try {
      const inspection = sessionEvidence(
        session,
        (
          await mcp.callTool({
            name: "inspect_native_api",
            arguments: { procedure: "fixture_main" },
          })
        ).structuredContent,
      );
      expect(inspection.normalized_result).toMatchObject({
        procedure: { address: "0x401000", name: "fixture_main" },
        boundary: {
          available: true,
          return_type: { data_type: "int", confidence: "medium" },
          jump_tables: [
            {
              dispatch_address: "0x401010",
              data_sources: [{ address: "0x403000" }],
              mappings: [{ case_value: 0, target_address: "0x401020" }],
              default_targets: [
                { target_address: "0x401030", confidence: "high" },
              ],
            },
          ],
        },
        unsupported_branches: [],
        residual_unknowns: [],
      });
      expect(
        (
          await mcp.callTool({
            name: "list_unknowns",
            arguments: {},
          })
        ).structuredContent,
      ).toMatchObject({ result: { items: [] } });
    } finally {
      await harness.close();
    }
  }, 30_000);
});
