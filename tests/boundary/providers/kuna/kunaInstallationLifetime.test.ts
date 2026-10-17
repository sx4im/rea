import { regularFileCancellation } from "../../../../src/filesystem/OwnedRegularFile.js";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const gates = vi.hoisted(() => {
  const createGate = () => {
    let enter!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    return { started, hold, enter, release };
  };
  return {
    createGate,
    hashClose: createGate(),
    shebangRead: createGate(),
    opens: 0,
    failClose: false,
  };
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
        const index = gates.opens++;
        return {
          get fd() {
            return handle.fd;
          },
          stat: (...statArgs: Parameters<typeof handle.stat>) =>
            handle.stat(...statArgs),
          read: async (...readArgs: Parameters<typeof handle.read>) => {
            if (index === 1) {
              gates.shebangRead.enter();
              await gates.shebangRead.hold;
            }
            return handle.read(...readArgs);
          },
          close: async () => {
            if (index === 0) {
              gates.hashClose.enter();
              await gates.hashClose.hold;
            }
            if (gates.failClose)
              throw new Error("controlled final close refusal");
            await handle.close();
          },
        } as unknown as typeof handle;
      },
    ),
  };
});

import { ArtifactResourceScope } from "../../../../src/artifacts/ArtifactResourceScope.js";
import type { FileCloseResourceOwner } from "../../../../src/application/AnalysisProvider.js";
import { inspectKunaInstallation } from "../../../../src/kuna/KunaInstallation.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeKuna } from "./fakeKuna.js";
import { session } from "./kunaSessionFixture.js";

beforeEach(() => {
  gates.opens = 0;
  gates.failClose = false;
  gates.hashClose = gates.createGate();
  gates.shebangRead = gates.createGate();
});

afterEach(() => {
  gates.failClose = false;
  gates.hashClose.release();
  gates.shebangRead.release();
});

it
  .skipIf(process.platform === "win32")
  .each(["hash-close", "shebang-read"] as const)(
  "keeps installation cleanup waiting for its active phase when cancelled during %s",
  async (phase) => {
    const root = await createTestTempDirectory("rea-kuna-inspection-lifetime-");
    const executable = await writeFakeKuna(root);
    const scope = new ArtifactResourceScope();
    const fileCloseResources: FileCloseResourceOwner = {
      retain: (owner, resource) =>
        scope.retain({
          kind: "lease",
          resource,
          lease: { release: () => owner.close() },
        }),
      run: (operation) => scope.run(operation),
    };
    const controller = new AbortController();
    const inspection = inspectKunaInstallation(
      { REA_KUNA_COMMAND: executable },
      { fileCloseResources, signal: controller.signal },
    );

    const inspectionOutcome = inspection.then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({ ok: false as const, error }),
    );
    let cleanup: Promise<void> | undefined;
    try {
      await gates.hashClose.started;
      cleanup = scope.retryCleanup();
      let cleanupFinished = false;
      void cleanup.then(() => {
        cleanupFinished = true;
      });
      await Promise.resolve();
      expect(cleanupFinished).toBe(false);
      if (phase === "hash-close") controller.abort();
      gates.hashClose.release();
      const reachedShebang = await Promise.race([
        gates.shebangRead.started.then(() => true),
        inspection.then(
          () => false,
          () => false,
        ),
      ]);
      expect(reachedShebang).toBe(phase === "shebang-read");
      if (phase === "shebang-read") {
        controller.abort();
        await Promise.resolve();
        expect(cleanupFinished).toBe(false);
      }

      gates.shebangRead.release();
      const failure: unknown = await inspection.catch(
        (cause: unknown) => cause,
      );
      const cancellation = regularFileCancellation(failure);
      expect(cancellation).toBeDefined();
      expect(cancellation?.reason).toBe(controller.signal.reason);
      await expect(cleanup).resolves.toBeUndefined();
      expect(gates.opens).toBe(phase === "hash-close" ? 1 : 2);
      expect(scope.hasPending).toBe(false);
    } finally {
      gates.hashClose.release();
      gates.shebangRead.release();
      await inspectionOutcome;
      await cleanup;
      await scope.close();
    }
  },
);

it
  .skipIf(process.platform === "win32")
  .each(["hash-close", "shebang-read", "close-refusal"] as const)(
  "joins session acquisition finalization and retains cleanup retry during %s cancellation",
  async (phase) => {
    gates.hashClose.release();
    gates.shebangRead.release();
    const fixture = await session("rea-kuna-session-finalization-");
    gates.opens = 0;
    gates.hashClose = gates.createGate();
    gates.shebangRead = gates.createGate();
    const client = fixture.open();
    const controller = new AbortController();
    const reason = { selected: "caller reason" };
    const pending = client.execute("health", {}, { signal: controller.signal });
    let finished = false;
    let replacement: ReturnType<typeof client.execute> | undefined;
    void pending.then(() => {
      finished = true;
    });
    try {
      await gates.hashClose.started;
      if (phase === "shebang-read") {
        gates.hashClose.release();
        await gates.shebangRead.started;
      }
      controller.abort(reason);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(finished).toBe(false);
      if (phase === "hash-close") replacement = client.execute("health", {});
      gates.failClose = phase === "close-refusal";
      gates.hashClose.release();
      gates.shebangRead.release();
      const result = await pending;
      if (result.ok) throw new Error("Expected interrupted installation");
      if (phase === "close-refusal") {
        expect(result.error.cleanupIncomplete).toBe(true);
        const retained = await client.execute("health", {});
        if (retained.ok) throw new Error("Expected retained cleanup failure");
        expect(retained.error).toBe(result.error);
        expect((await client.close()).ok).toBe(false);
        gates.failClose = false;
        expect((await client.close()).ok).toBe(true);
        expect(result.error.cleanupIncomplete).toBe(false);
      } else {
        expect(result.error._tag).toBe("AnalysisCancelledError");
        expect(result.error.cause).toBe(reason);
        expect(result.error.cleanupIncomplete).toBe(false);
        if (replacement !== undefined)
          expect((await replacement).ok).toBe(true);
        expect((await client.close()).ok).toBe(true);
      }
    } finally {
      gates.failClose = false;
      gates.hashClose.release();
      gates.shebangRead.release();
      await pending;
      await replacement;
      expect((await client.close()).ok).toBe(true);
    }
  },
);
