import type { FileHandle } from "node:fs/promises";
import { err, ok, type Result } from "../domain/result.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  ArtifactFileCleanupFailure,
  withArtifactRegularFile,
} from "../artifacts/ArtifactFileOperation.js";
import type { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";

/** One trace's readback descriptors, separate from the facts already read. */
export class LldbReadbackFiles {
  readonly #resources = new ArtifactResourceScope();
  readonly #targetPids = new Map<string, number>();
  readonly #failed = new Map<
    AnalysisCleanupLease,
    { readonly path: string; readonly cause: ArtifactFileCleanupFailure }
  >();

  get hasPending(): boolean {
    return this.#resources.hasPending;
  }

  get cleanupResources(): readonly string[] {
    return [
      ...new Set(
        [...this.#failed]
          .filter(([lease]) => !lease.released)
          .map(([, failure]) => failure.path),
      ),
    ];
  }

  get cleanupCause(): unknown {
    const failures = [...this.#failed]
      .filter(([lease]) => !lease.released)
      .map(([, failure]) => failure.cause);
    return failures.length === 0
      ? undefined
      : new AggregateError(
          failures,
          "LLDB readback descriptors remain open or unconfirmed",
        );
  }

  /** Preserve a completed value even if final close transfers its owner here. */
  async read<Value>(
    path: string,
    read: (handle: FileHandle) => Promise<Value>,
  ): Promise<Result<Value, unknown>> {
    const blocked = [...this.#failed].find(
      ([lease, failure]) => !lease.released && failure.path === path,
    );
    if (blocked !== undefined) return err(blocked[1].cause);
    let completed: { readonly value: Value } | undefined;
    try {
      return ok(
        await withArtifactRegularFile(
          path,
          this.#resources,
          undefined,
          async (handle) => {
            const value = await read(handle);
            completed = { value };
            return value;
          },
        ),
      );
    } catch (cause: unknown) {
      if (cause instanceof ArtifactFileCleanupFailure)
        this.#failed.set(cause.cleanupLease, { path, cause });
      return completed === undefined ? err(cause) : ok(completed.value);
    }
  }

  /** The producer publishes one target PID per runtime; retain its parsed fact. */
  async readTargetPid(path: string): Promise<number | undefined> {
    const known = this.#targetPids.get(path);
    if (known !== undefined) return known;
    const contents = await this.read(path, async (file) =>
      (await file.readFile("utf8")).trim(),
    );
    if (!contents.ok || !/^[1-9]\d*$/u.test(contents.value)) return undefined;
    const pid = Number(contents.value);
    if (!Number.isSafeInteger(pid)) return undefined;
    this.#targetPids.set(path, pid);
    return pid;
  }

  async retryCleanup(): Promise<void> {
    try {
      await this.#resources.retryCleanup();
    } finally {
      for (const lease of this.#failed.keys())
        if (lease.released) this.#failed.delete(lease);
    }
  }
}
