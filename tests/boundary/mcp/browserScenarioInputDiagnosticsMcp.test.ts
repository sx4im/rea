import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { join, resolve } from "node:path";
import { expect } from "vitest";
import { z } from "zod";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const scenarios = [
  {
    name: "undeclared secret references",
    issuePath: ["secrets"],
    issueMessage: "Secret reference pw is not declared",
    actions: [
      {
        step_id: "pw",
        action: "fill",
        locator: { kind: "css", selector: "#pw" },
        value: { source: "secret", secret_id: "pw" },
      },
    ],
  },
  {
    name: "duplicate action step IDs",
    issuePath: ["actions"],
    issueMessage: "Action step IDs must be unique",
    actions: [
      { step_id: "wait", action: "wait_for_timeout", duration_ms: 1 },
      { step_id: "wait", action: "wait_for_timeout", duration_ms: 1 },
    ],
  },
] as const;

cliTest(
  "projects refined browser scenario validation into CLI-equivalent diagnostics over stdio MCP",
  async ({ cli }) => {
    const home = await createTestTempDirectory(
      "rea-browser-scenario-mcp-home-",
    );
    const client = new Client({
      name: "browser-scenario-input-diagnostics",
      version: "1",
    });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("scripts/rea.mjs"), "mcp"],
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH ?? "",
        HOME: home,
        REA_LOG_LEVEL: "silent",
      },
      stderr: "pipe",
    });
    transport.stderr?.on("data", () => undefined);

    try {
      await client.connect(transport);
      const tool = (await client.listTools()).tools.find(
        ({ name }) => name === "capture_browser_scenario",
      );
      if (tool === undefined) throw new Error("Missing browser scenario tool");
      const validate = new Ajv2020({
        strict: false,
        validateFormats: false,
      }).compile(tool.inputSchema);

      for (const scenario of scenarios) {
        const input = {
          browser: {
            mode: "launch",
            executable_path: join(home, "missing-chromium"),
          },
          start_url: { url: "http://127.0.0.1:1/", query: [] },
          actions: scenario.actions,
          secrets: [],
        };
        expect(
          validate(input),
          `${scenario.name}: ${JSON.stringify(validate.errors)}`,
        ).toBe(true);

        const cliResult = await cli.run({
          arguments: [
            "capture-browser-scenario",
            JSON.stringify(input),
            "--json",
          ],
          environment: { HOME: home, REA_LOG_LEVEL: "silent" },
        });
        expect(cliResult.exitCode).toBe(1);
        const cliDiagnostic = z
          .record(z.string(), z.unknown())
          .parse(cliResult.json);
        expect(typeof cliDiagnostic.error).toBe("string");
        delete cliDiagnostic.error;
        expect(cliDiagnostic).toMatchObject({
          code: "invalid_request",
          category: "invalid_input",
          retryable: true,
          remediation: { action: "Correct the listed arguments and retry." },
          details: {
            operation: "capture_browser_scenario",
            issues: [
              {
                path: scenario.issuePath,
                reason: "invalid_value",
                message: scenario.issueMessage,
              },
            ],
          },
        });

        const mcpResult = await client.callTool({
          name: tool.name,
          arguments: input,
        });
        expect(mcpResult.structuredContent).toBeUndefined();
        expect(parseMcpToolError(mcpResult).error).toEqual(cliDiagnostic);
        await expect(client.ping()).resolves.toEqual({});
      }
    } finally {
      await Promise.all([client.close(), transport.close()]);
    }
  },
  60_000,
);
