import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { copyFile, lstat, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

const output = ".cache/ci-build-cache";

function readTasks() {
  const { tasks } = z
    .object({
      tasks: z
        .array(
          z.object({
            taskId: z.string().min(1),
            // The pinned Turbo version uses eager 64-bit hexadecimal hashes.
            hash: z.string().regex(/^[0-9a-f]{16}$/u),
          }),
        )
        .min(1),
    })
    .parse(JSON.parse(readFileSync(0, "utf8")));
  const identities = new Set();
  for (const { taskId } of tasks) {
    if (identities.has(taskId))
      throw new Error(`Duplicate portable build task: ${taskId}`);
    identities.add(taskId);
  }
  return tasks;
}

async function snapshot(tasks) {
  await mkdir(output, { recursive: true });
  let files = 0;
  let bytes = 0;
  try {
    for (const hash of new Set(tasks.map((task) => task.hash))) {
      for (const suffix of [".tar.zst", "-meta.json", "-manifest.json"]) {
        const name = `${hash}${suffix}`;
        const source = join(".turbo/cache", name);
        const entry = await lstat(source).catch((error) => {
          // Manifests are not present in every supported local cache entry.
          if (suffix === "-manifest.json" && error.code === "ENOENT")
            return undefined;
          throw error;
        });
        if (!entry) continue;
        if (!entry.isFile())
          throw new Error(
            `Portable build cache entry must be a regular file: ${source}`,
          );
        await copyFile(source, join(output, name));
        files++;
        bytes += entry.size;
      }
    }
  } catch (error) {
    await rm(output, { recursive: true, force: true });
    throw error;
  }
  console.log(
    JSON.stringify({ tasks: tasks.length, files, bytes, path: output }),
  );
}

const [mode, ...extra] = process.argv.slice(2);
if (extra.length || !["key", "snapshot"].includes(mode))
  throw new Error(
    "Usage: portable-build-cache.mjs key|snapshot < turbo-dry-plan.json",
  );
// Remove any earlier snapshot before parsing: a failed second invocation must
// never leave an old successful artifact eligible for upload.
if (mode === "snapshot") await rm(output, { recursive: true, force: true });
const tasks = readTasks();
if (mode === "key") {
  const prefix = z
    .string()
    .min(1)
    .regex(/^[^\r\n]+$/u)
    .parse(process.env.BUILD_CACHE_PREFIX);
  const hashes = tasks.map(({ taskId, hash }) => `${taskId}:${hash}`).sort();
  const digest = createHash("sha256").update(hashes.join("\n")).digest("hex");
  console.log(`key=${prefix}-${digest}\nprefix=${prefix}-`);
} else {
  await snapshot(tasks);
}
