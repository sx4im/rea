import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, expect, it, vi } from "vitest";
import { AnalysisError } from "../../../../src/domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";

import { ArtifactResourceScope } from "../../../../src/artifacts/ArtifactResourceScope.js";
import type { FileCloseResourceOwner } from "../../../../src/application/AnalysisProvider.js";

const injected = vi.hoisted(() => ({
  failNextClose: false,
  holdCloseFailures: false,
  releaseCloseFailures: false,
  closeCalls: 0,
  failCloseReadStage: undefined as "fingerprint" | "shebang" | undefined,
  failReadStage: undefined as "fingerprint" | "shebang" | undefined,
  abortOnReadFailure: undefined as (() => void) | undefined,
  handles: [] as import("node:fs/promises").FileHandle[],
}));

afterEach(async () => {
  injected.failNextClose = false;
  injected.holdCloseFailures = false;
  injected.releaseCloseFailures = false;
  injected.closeCalls = 0;
  injected.failCloseReadStage = undefined;
  injected.failReadStage = undefined;
  injected.abortOnReadFailure = undefined;
  for (const handle of injected.handles.splice(0))
    if (handle.fd >= 0) await handle.close();
});

vi.mock("../../../../src/filesystem/RegularFile.js", async (importOriginal) => {
  const original =
    await importOriginal<
      typeof import("../../../../src/filesystem/RegularFile.js")
    >();
  return {
    ...original,
    openRegularFile: vi.fn(
      async (...args: Parameters<typeof original.openRegularFile>) => {
        const handle = await original.openRegularFile(...args);
        injected.handles.push(handle);
        const failNextClose = injected.failNextClose;
        const failCloseReadStage = injected.failCloseReadStage;
        const failReadStage = injected.failReadStage;
        if (
          !failNextClose &&
          !injected.holdCloseFailures &&
          !failCloseReadStage &&
          !failReadStage
        )
          return handle;
        injected.failNextClose = false;
        let readStageMatched = false;
        let failedClose = false;
        return {
          get fd() {
            return handle.fd;
          },
          stat: (...statArgs: Parameters<typeof handle.stat>) =>
            handle.stat(...statArgs),
          read: (
            buffer: Buffer,
            offset: number,
            length: number,
            position: number,
          ) => {
            if (
              (failReadStage === "fingerprint" && length > 2) ||
              (failReadStage === "shebang" && length === 2)
            ) {
              readStageMatched = true;
              injected.abortOnReadFailure?.();
              throw new Error("injected read fault");
            }
            if (failCloseReadStage === "fingerprint" && length > 2)
              readStageMatched = true;
            if (failCloseReadStage === "shebang" && length === 2)
              readStageMatched = true;
            return handle.read(buffer, offset, length, position);
          },
          close: async () => {
            injected.closeCalls += 1;
            if (
              (failNextClose && !failedClose) ||
              (readStageMatched && !failedClose) ||
              (injected.holdCloseFailures && !injected.releaseCloseFailures)
            ) {
              failedClose = true;
              throw new Error("injected close fault");
            }
            await handle.close();
          },
        } as unknown as typeof handle;
      },
    ),
  };
});

import { AnalysisProviderRegistry } from "../../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../../src/application/binary/BinarySessionComposition.js";
import { KunaTargetCommands } from "../../../../src/kuna/KunaTargetCommands.js";
import { KunaProjectCache } from "../../../../src/kuna/KunaProjectCache.js";
import { inspectKunaProvider } from "../../../../src/kuna/KunaDoctor.js";
import { inspectKunaInstallationOwned } from "./kunaFileCloseOwner.js";
import { fakeKunaCalls } from "./fakeKuna.js";
import { run, session } from "./kunaSessionFixture.js";

it.skipIf(process.platform === "win32").each(
  (["fingerprint", "shebang"] as const).flatMap((stage) =>
    (["health", "search_procedures"] as const).map((operation) => ({
      stage,
      operation,
    })),
  ),
)(
  "resolves $operation installation cleanup ownership after a $stage close failure is retried",
  async ({ stage, operation }) => {
    const fixture = await session("rea-kuna-installation-owner-resolution-");
    const client = fixture.open();
    injected.closeCalls = 0;
    injected.failCloseReadStage = stage;
    try {
      const inspected = await client.execute(
        operation,
        operation === "health"
          ? {}
          : {
              pattern: "main",
              mode: "literal",
              case_sensitive: false,
            },
      );
      expect(inspected.ok).toBe(false);
      if (inspected.ok)
        throw new Error("installation inspection unexpectedly passed");
      const originatingError = inspected.error;
      const originalCause = originatingError.cause;
      expect(projectAnalysisError(originatingError).details).toMatchObject({
        operation,
      });
      expect(originatingError).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [fixture.kuna],
      });
      const producer =
        operation === "health" ? originatingError : originalCause;
      expect(producer).toBeInstanceOf(AnalysisError);
      if (!(producer instanceof AnalysisError))
        throw new Error("Missing producer error");
      expect(producer.cause).toMatchObject({
        name: "RegularFileCleanupFailure",
      });
      const failedCloseCall = stage === "fingerprint" ? 1 : 2;
      expect(injected.closeCalls).toBe(failedCloseCall);

      expect(await client.close()).toEqual({ ok: true, value: null });
      expect(originatingError.cleanupIncomplete).toBe(false);
      expect(producer.cleanupIncomplete).toBe(false);
      expect(originatingError.cause).toBe(originalCause);
      expect(injected.closeCalls).toBe(failedCloseCall + 1);
    } finally {
      injected.failCloseReadStage = undefined;
      const closed = await client.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "keeps the physical hash read failure primary when cancellation and close failure follow",
  async () => {
    const fixture = await session("rea-kuna-cancelled-read-close-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const controller = new AbortController();
    const commands = new KunaTargetCommands(fixture.target, {
      signal: controller.signal,
    });
    injected.failReadStage = "fingerprint";
    injected.abortOnReadFailure = () => controller.abort();
    let originatingError:
      | import("../../../../src/domain/analysisErrorBase.js").AnalysisError
      | undefined;
    try {
      const result = await commands.run({
        installation: installed.value,
        operation: "list_procedures",
        arguments: (input) => ["functions", input, "--json"],
        deadline: { setting: "REA_KUNA_TIMEOUT_MS", ms: 10_000 },
        outputBytes: 1024 * 1024,
        signal: controller.signal,
      });
      if (result.ok) throw new Error("injected cancelled read passed");
      originatingError = result.error;
      expect(result.error).toMatchObject({
        _tag: "ProviderAdapterError",
        cleanupIncomplete: true,
        cleanupResources: [installed.value.executable],
        diagnostics: {
          primary_error: {
            code: "execution_failure",
            message: expect.stringContaining("injected read fault"),
          },
        },
      });
    } finally {
      injected.failReadStage = undefined;
      injected.abortOnReadFailure = undefined;
      const closed = await commands.close();
      if (!closed.ok) throw closed.error;
      expect(originatingError?.cleanupIncomplete).toBe(false);
    }
  },
);

it.skipIf(process.platform === "win32")(
  "resolves an export's typed read failure after the cache retries its exact descriptor",
  async () => {
    const fixture = await session("rea-kuna-export-read-close-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const cache = new KunaProjectCache(fixture.cacheRoot, {
      maxBytes: 64 * 1024 ** 2,
    });
    injected.failReadStage = "fingerprint";
    try {
      const result = await cache.build({
        installation: installed.value,
        targetPath: fixture.target.path,
        targetSha256: fixture.target.sha256,
      });
      if (result.ok) throw new Error("injected export hash read passed");
      const originatingError = result.error;
      expect(originatingError).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [fixture.kuna],
      });
      expect(originatingError.userMessage).toContain("injected read fault");
      expect(await cache.close()).toEqual({ ok: true, value: null });
      expect(originatingError.cleanupIncomplete).toBe(false);
    } finally {
      injected.failReadStage = undefined;
      const closed = await cache.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "preserves a hash read failure when closing its descriptor also fails",
  async () => {
    const fixture = await session("rea-kuna-read-and-close-failure-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const controller = new AbortController();
    const commands = new KunaTargetCommands(fixture.target, {
      signal: controller.signal,
    });
    injected.failReadStage = "fingerprint";
    try {
      const result = await commands.run({
        installation: installed.value,
        operation: "list_procedures",
        arguments: (input) => ["functions", input, "--json"],
        deadline: { setting: "REA_KUNA_TIMEOUT_MS", ms: 10_000 },
        outputBytes: 1024 * 1024,
        signal: controller.signal,
      });
      if (result.ok) throw new Error("injected hash read failure passed");
      expect(result.error.cleanupIncomplete).toBe(true);
      expect(result.error.userMessage).toContain("injected read fault");
      expect(result.error.cause).toBeInstanceOf(AggregateError);
      const errors = (result.error.cause as AggregateError).errors;
      expect(errors[0]).toMatchObject({
        cause: { message: "injected read fault" },
      });
      expect(errors[1]).toMatchObject({
        cleanupResources: [installed.value.executable],
      });
      expect(result.error.cleanupResources).toEqual([
        installed.value.executable,
      ]);
    } finally {
      injected.failReadStage = undefined;
      controller.abort();
      const closed = await commands.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "retains and retries the exact Kuna executable hash owner without running Kuna",
  async () => {
    const fixture = await session("rea-kuna-hash-owner-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const controller = new AbortController();
    const commands = new KunaTargetCommands(fixture.target, {
      signal: controller.signal,
    });
    injected.closeCalls = 0;
    injected.failNextClose = true;
    try {
      const result = await commands.run({
        installation: installed.value,
        operation: "list_procedures",
        arguments: (input) => ["functions", input, "--json"],
        deadline: { setting: "REA_KUNA_TIMEOUT_MS", ms: 10_000 },
        outputBytes: 1024 * 1024,
        signal: controller.signal,
      });
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Kuna command unexpectedly ran");
      const originatingError = result.error;
      const originalCause = originatingError.cause;
      expect(result.error).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [installed.value.executable],
      });
      expect(await commands.close()).toEqual({ ok: true, value: null });
      expect(originatingError.cleanupIncomplete).toBe(false);
      expect(originatingError.cause).toBe(originalCause);
      expect(injected.closeCalls).toBe(2);
      expect(
        (await fakeKunaCalls(fixture.kuna)).map(({ argv }) => argv),
      ).toEqual([["--version"], ["--version"]]);
    } finally {
      controller.abort();
      const closed = await commands.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "blocks command and prepare admission while one retained executable hash owner keeps failing",
  async () => {
    const fixture = await session("rea-kuna-hash-owner-admission-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const controller = new AbortController();
    const commands = new KunaTargetCommands(fixture.target, {
      signal: controller.signal,
    });
    const originalHandleCount = injected.handles.length;
    let releasedAdmissions = 0;
    injected.closeCalls = 0;
    injected.holdCloseFailures = true;
    injected.releaseCloseFailures = false;
    try {
      const request = () =>
        commands.run({
          installation: installed.value,
          operation: "list_procedures",
          arguments: (input) => ["functions", input, "--json"],
          deadline: { setting: "REA_KUNA_TIMEOUT_MS", ms: 10_000 },
          outputBytes: 1024 * 1024,
          signal: controller.signal,
          releaseRun: () => {
            releasedAdmissions += 1;
          },
        });

      const first = await request();
      expect(first.ok).toBe(false);
      if (first.ok)
        throw new Error("hash descriptor close unexpectedly passed");
      const blocked = await request();
      expect(blocked.ok).toBe(false);
      if (blocked.ok) throw new Error("Kuna ran with retained hash cleanup");
      expect(blocked.error).toMatchObject({ cleanupIncomplete: true });
      const prepared = await commands.prepare();
      expect(prepared.ok).toBe(false);
      if (prepared.ok) throw new Error("prepare passed retained hash cleanup");
      expect(prepared.error).toMatchObject({ cleanupIncomplete: true });

      expect(injected.closeCalls).toBe(3);
      expect(injected.handles.length - originalHandleCount).toBe(1);
      expect(releasedAdmissions).toBe(2);
      expect(
        (await fakeKunaCalls(fixture.kuna)).map(({ argv }) => argv[0]),
      ).not.toContain("functions");
    } finally {
      injected.releaseCloseFailures = true;
      controller.abort();
      const closed = await commands.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "resolves the originating hash cleanup error when its exact owner closes on retry",
  async () => {
    const fixture = await session("rea-kuna-hash-owner-resolution-");
    const installed = await inspectKunaInstallationOwned({
      REA_KUNA_COMMAND: fixture.kuna,
      REA_KUNA_CACHE_DIR: fixture.cacheRoot,
    });
    if (!installed.ok) throw new Error(installed.error.reason);
    const controller = new AbortController();
    const commands = new KunaTargetCommands(fixture.target, {
      signal: controller.signal,
    });
    injected.closeCalls = 0;
    injected.holdCloseFailures = true;
    injected.releaseCloseFailures = false;
    try {
      const request = () =>
        commands.run({
          installation: installed.value,
          operation: "list_procedures",
          arguments: (input) => ["functions", input, "--json"],
          deadline: { setting: "REA_KUNA_TIMEOUT_MS", ms: 10_000 },
          outputBytes: 1024 * 1024,
          signal: controller.signal,
        });

      const first = await request();
      expect(first.ok).toBe(false);
      if (first.ok)
        throw new Error("hash descriptor close unexpectedly passed");
      const originatingError = first.error;
      const originalCause = originatingError.cause;
      expect(originatingError).toMatchObject({ cleanupIncomplete: true });
      expect(originalCause).toMatchObject({
        name: "RegularFileCleanupFailure",
      });

      const blocked = await request();
      expect(blocked.ok).toBe(false);
      if (blocked.ok) throw new Error("Kuna ran with retained hash cleanup");
      expect(blocked.error).toMatchObject({ cleanupIncomplete: true });
      expect(injected.closeCalls).toBe(2);

      injected.releaseCloseFailures = true;
      const recovered = await request();
      expect(recovered.ok).toBe(true);
      expect(originatingError.cleanupIncomplete).toBe(false);
      expect(originatingError.cause).toBe(originalCause);
      expect(injected.closeCalls).toBe(4);
      expect(
        (await fakeKunaCalls(fixture.kuna)).filter(
          ({ argv }) => argv[0] === "functions",
        ),
      ).toHaveLength(1);
    } finally {
      injected.releaseCloseFailures = true;
      controller.abort();
      const closed = await commands.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it
  .skipIf(process.platform === "win32")
  .each([{ stage: "fingerprint" }, { stage: "shebang" }] as const)(
  "resolves the Kuna profile cleanup error after its $stage descriptor closes",
  async ({ stage }) => {
    const fixture = await session("rea-kuna-profile-owner-resolution-");
    const binary = composeBinarySession(
      new AnalysisProviderRegistry([fixture.provider]),
    );
    injected.closeCalls = 0;
    injected.failCloseReadStage = stage;
    try {
      const resolved = await binary.previewTarget(fixture.target);
      expect(resolved.ok).toBe(false);
      if (resolved.ok)
        throw new Error("Kuna profile inspection unexpectedly passed");
      const originatingError = resolved.error;
      expect(originatingError).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [fixture.kuna],
      });
      expect(await binary.status()).toMatchObject({ cleanup_pending: true });

      expect(await binary.close()).toEqual({ ok: true, value: null });
      expect(originatingError.cleanupIncomplete).toBe(false);
      expect(injected.closeCalls).toBe(stage === "fingerprint" ? 2 : 3);
      expect(await binary.status()).toMatchObject({ cleanup_pending: false });
    } finally {
      injected.failCloseReadStage = undefined;
      const closed = await binary.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it.skipIf(process.platform === "win32")(
  "drains a Kuna candidate's retained hash owner when the binary session closes without an active client",
  async () => {
    const fixture = await session("rea-kuna-candidate-hash-owner-");
    const binary = composeBinarySession(
      new AnalysisProviderRegistry([fixture.provider]),
    );
    injected.closeCalls = 0;
    injected.holdCloseFailures = true;
    injected.releaseCloseFailures = false;

    const resolved = await binary.previewTarget(fixture.target);
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("Kuna readiness unexpectedly succeeded");
    expect(resolved.error).toMatchObject({
      cleanupIncomplete: true,
      cleanupResources: [fixture.kuna],
    });
    expect(injected.closeCalls).toBe(1);
    expect(await binary.status()).toMatchObject({
      open: false,
      cleanup_pending: true,
    });
    expect(await binary.close()).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true, cleanupResources: [fixture.kuna] },
    });
    expect(injected.closeCalls).toBe(2);
    expect(await binary.status()).toMatchObject({ cleanup_pending: true });

    injected.releaseCloseFailures = true;
    expect(await binary.close()).toEqual({ ok: true, value: null });
    expect(injected.closeCalls).toBe(3);
    expect(await binary.status()).toMatchObject({ cleanup_pending: false });
    expect((await fakeKunaCalls(fixture.kuna)).map(({ argv }) => argv)).toEqual(
      [["--version"], ["--version"]],
    );
  },
);

it.skipIf(process.platform === "win32")(
  "retains a failed Kuna doctor hash in the supplied lifecycle owner",
  async () => {
    const fixture = await session("rea-kuna-doctor-hash-owner-");
    injected.closeCalls = 0;
    injected.failNextClose = true;
    const resources = new ArtifactResourceScope();
    const fileCloseResources: FileCloseResourceOwner = {
      retain: (owner, resource) =>
        resources.retain({
          kind: "lease",
          resource,
          lease: { release: () => owner.close() },
        }),
      run: (operation) => resources.run(operation),
    };
    try {
      const inspection = await inspectKunaProvider(
        {
          REA_KUNA_COMMAND: fixture.kuna,
          REA_KUNA_CACHE_DIR: fixture.cacheRoot,
        },
        process.platform,
        { fileCloseResources },
      );
      expect(inspection.checks[0]).toMatchObject({
        ok: false,
        code: "cleanup_incomplete",
      });
      expect(injected.closeCalls).toBe(1);
      await resources.close();
      expect(injected.closeCalls).toBe(2);
    } finally {
      await resources.close();
    }
    expect((await fakeKunaCalls(fixture.kuna)).map(({ argv }) => argv)).toEqual(
      [["--version"], ["--version"]],
    );
  },
);

it.skipIf(process.platform === "win32")(
  "drains shared cache cleanup outside a retired client's target key",
  async () => {
    const fixture = await session("rea-kuna-session-cache-cleanup-");
    const binary = composeBinarySession(
      new AnalysisProviderRegistry([fixture.provider]),
    );
    const retired = join(fixture.cacheRoot, "trash", "retired");
    await mkdir(retired, { recursive: true });
    await writeFile(join(retired, "evidence"), "retained export");
    await chmod(retired, 0o500);
    const client = fixture.open();
    try {
      await run(client, "procedure_assembly", { procedure: "main" });
      // Target-key cleanup cannot release maintenance retained for another key.
      expect(await client.close()).toEqual({ ok: true, value: null });
      expect(await binary.close()).toMatchObject({
        ok: false,
        error: { cleanupIncomplete: true, cleanupResources: [retired] },
      });
      expect(await binary.status()).toMatchObject({
        open: false,
        cleanup_pending: true,
      });
      expect(await readFile(join(retired, "evidence"), "utf8")).toBe(
        "retained export",
      );
      await chmod(retired, 0o700);
      expect(await binary.close()).toEqual({ ok: true, value: null });
      expect(await binary.status()).toMatchObject({ cleanup_pending: false });
      await expect(readFile(join(retired, "evidence"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await chmod(retired, 0o700).catch(() => {});
      await client.close();
      await binary.close();
    }
  },
);
