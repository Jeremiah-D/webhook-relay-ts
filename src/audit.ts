import { appendFileSync, readFileSync } from "node:fs";

/**
 * Append-only JSONL audit log. Each line is a JSON object containing the
 * caller's event fields plus an ISO-8601 `ts` timestamp. Kept dependency-free
 * so the log can be inspected with plain `jq`/text tools.
 */
export class AuditLog {
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  append(event: object): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...event });
    appendFileSync(this.path, line + "\n", "utf8");
  }

  readAll(): object[] {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return [];
    }
    const out: object[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;
      try {
        out.push(JSON.parse(trimmed));
      } catch {
        // Skip malformed lines; never let one bad line break reads.
      }
    }
    return out;
  }
}
