import { createRequire } from "node:module";
import type { TerminalRetention } from "../../domain/process/processCaptureCoverage.js";
import type { BoundedProcessTextNormalization } from "./ProcessNormalization.js";

import type {
  RecordProcessCaptureEvent,
  RenderedTerminalFrame,
} from "../../domain/process/processCapture.js";

const require = createRequire(import.meta.url);
// SAFETY: both pinned xterm packages publish CommonJS at runtime and matching declarations.
const HeadlessPackage =
  require("@xterm/headless") as typeof import("@xterm/headless");
// SAFETY: the addon package is pinned with the compatible headless xterm release.
const SerializePackage =
  require("@xterm/addon-serialize") as typeof import("@xterm/addon-serialize");

const TRAILING_SPACES = / +$/u;

// [low, high] code-point ranges for terminal cell width. Combining marks ride
// on the previous cell (width 0); East Asian wide and fullwidth ranges occupy
// two cells; everything else is one cell.
const ZERO_WIDTH_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x300, 0x36f],
  [0x1ab0, 0x1aff],
  [0x1dc0, 0x1dff],
  [0x20d0, 0x20ff],
  [0xfe20, 0xfe2f],
];

const WIDE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x1100, 0x115f],
  [0x2e80, 0xa4cf],
  [0xac00, 0xd7a3],
  [0xf900, 0xfaff],
  [0xfe30, 0xfe4f],
  [0xff00, 0xff60],
  [0xffe0, 0xffe6],
  [0x20000, 0x3fffd],
];

const inRanges = (
  codePoint: number,
  ranges: ReadonlyArray<readonly [number, number]>,
): boolean =>
  ranges.some(([low, high]) => codePoint >= low && codePoint <= high);

// xterm reports rows by cell width, but JavaScript string length counts a
// two-cell character as one. Measure by display width so the retained row
// keeps exactly the terminal row's cells instead of inventing a blank one.
const cellWidth = (codePoint: number): number => {
  if (inRanges(codePoint, ZERO_WIDTH_RANGES)) return 0;
  if (inRanges(codePoint, WIDE_RANGES)) return 2;
  return 1;
};

const displayWidth = (value: string): number => {
  let width = 0;
  for (const char of value) width += cellWidth(char.codePointAt(0) ?? 0);
  return width;
};

/** padEnd counted in terminal cells, not UTF-16 code units. */
const padToCellWidth = (value: string, columns: number): string => {
  const deficit = columns - displayWidth(value);
  return deficit > 0 ? value + " ".repeat(deficit) : value;
};

interface TerminalRendererOptions {
  readonly columns: number;
  readonly rows: number;
  readonly scrollback: number;
  readonly maxBytes: number;
  readonly normalize: (
    value: string,
    maxBytes: number,
  ) => BoundedProcessTextNormalization;
  readonly recordEvent?: RecordProcessCaptureEvent;
}

/**
 * Owns one headless terminal and serializes writes into deterministic frames.
 * Reconstructs bounded terminal states while raw PTY chunks remain authoritative.
 *
 * Rendered frames answer what an operator saw after control-sequence handling;
 * raw frames preserve byte/chunk differences that can render identically.
 * Comparisons retain both because neither representation subsumes the other.
 */
export class TerminalRenderer {
  readonly #terminal: InstanceType<typeof HeadlessPackage.Terminal>;
  readonly #serializeAddon = new SerializePackage.SerializeAddon();
  readonly #frames: RenderedTerminalFrame[] = [];
  #pending: Promise<void> = Promise.resolve();
  #capturedBytes = 0;
  #observedBytes = 0;
  #observedFrames = 0;
  #truncated = false;
  #unknownSizeFrames = 0;

  constructor(private readonly options: TerminalRendererOptions) {
    this.#terminal = new HeadlessPackage.Terminal({
      allowProposedApi: true,
      cols: options.columns,
      rows: options.rows,
      scrollback: options.scrollback,
    });
    this.#terminal.loadAddon(this.#serializeAddon);
  }

  /** Queue one PTY chunk and capture state only after xterm has parsed it. */
  write(data: string, atMs: number): void {
    this.#queue(
      () =>
        new Promise<void>((resolveWrite, rejectWrite) => {
          this.#terminal.write(data, () => {
            try {
              this.#capture(atMs);
              resolveWrite();
            } catch (error) {
              rejectWrite(error);
            }
          });
        }),
    );
  }

  /** Queue a terminal resize after every preceding write. */
  resize(columns: number, rows: number, atMs: number): void {
    this.#queue(() => {
      this.#terminal.resize(columns, rows);
      this.#capture(atMs);
    });
  }

  /** Await all queued parsing and return immutable rendered observations. */
  async frames(): Promise<readonly RenderedTerminalFrame[]> {
    await this.#pending;
    return structuredClone(this.#frames);
  }

  /** Whether a rendered observation exceeded its independent capture budget. */
  truncated(): boolean {
    return this.#truncated;
  }

  /** Budget accounting after awaiting queued writes with frames(). */
  retention(): TerminalRetention {
    return {
      budget_bytes: this.options.maxBytes,
      observed_bytes: this.#observedBytes,
      retained_bytes: this.#capturedBytes,
      observed_frames: this.#observedFrames,
      retained_frames: this.#frames.length,
      ...(this.#unknownSizeFrames === 0
        ? {}
        : { unknown_size_frames: this.#unknownSizeFrames }),
    };
  }

  /** Release addon and terminal resources after all writes settle. */
  async dispose(): Promise<void> {
    // frames() owns observation failures; cleanup reports only disposal failures.
    await this.#pending.catch(() => undefined);
    // xterm owns and disposes every addon loaded through loadAddon().
    this.#terminal.dispose();
  }

  #queue(operation: () => void | Promise<void>): void {
    this.#pending = this.#pending.then(operation);
    // PTY callbacks can fail before capture completion awaits frames(). Keep
    // the original rejection observable there without an unhandled rejection.
    void this.#pending.catch(() => undefined);
  }

  #capture(atMs: number): void {
    const buffer = this.#terminal.buffer.active;
    const lines: string[] = [];
    this.#observedFrames += 1;
    let remainingBytes = this.options.maxBytes - this.#capturedBytes;
    let bytes = 0;
    for (let row = 0; row < this.#terminal.rows; row += 1) {
      const line = buffer.getLine(buffer.viewportY + row);
      const paddedLine = padToCellWidth(
        line?.translateToString(false, 0, this.#terminal.cols) ?? "",
        this.#terminal.cols,
      );
      const trailingSpaceBytes = Buffer.byteLength(
        paddedLine.match(TRAILING_SPACES)?.[0] ?? "",
      );
      const normalized = this.options.normalize(
        paddedLine,
        Math.min(Number.MAX_SAFE_INTEGER, remainingBytes + trailingSpaceBytes),
      );
      if (normalized.state === "over_budget") {
        this.#unknownSizeFrames += 1;
        this.#truncated = true;
        return;
      }
      const normalizedLine = normalized.value.replace(TRAILING_SPACES, "");
      const lineBytes = Buffer.byteLength(normalizedLine);
      if (lineBytes > remainingBytes) {
        this.#unknownSizeFrames += 1;
        this.#truncated = true;
        return;
      }
      remainingBytes -= lineBytes;
      bytes += lineBytes;
      // Trailing blank cells carry no information beyond `columns`; dropping
      // them keeps sparse screens from costing a full row per blank line.
      lines.push(normalizedLine);
    }
    const normalizedState = this.options.normalize(
      this.#serializeAddon.serialize(),
      remainingBytes,
    );
    if (normalizedState.state === "over_budget") {
      this.#unknownSizeFrames += 1;
      this.#truncated = true;
      return;
    }
    bytes += normalizedState.utf8Bytes;
    this.#observedBytes += bytes;
    this.#capturedBytes += bytes;
    const sequence = this.#frames.length;
    this.#frames.push({
      sequence,
      at_ms: atMs,
      columns: this.#terminal.cols,
      rows: this.#terminal.rows,
      cursor_x: buffer.cursorX,
      cursor_y: buffer.cursorY,
      active_buffer: buffer.type,
      lines,
      serialized_state: normalizedState.value,
    });
    this.options.recordEvent?.("rendered_frames", sequence);
  }
}
