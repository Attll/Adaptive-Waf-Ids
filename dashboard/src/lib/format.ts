import type { EventRecord } from "../api";

export type Tone = "neutral" | "success" | "warning" | "danger" | "info" | "violet";
export type JsonRecord = Record<string, unknown>;

const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateTime = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const formatTime = (value: string | number | Date) => time.format(new Date(value));
export const formatDateTime = (value: string | number | Date) => dateTime.format(new Date(value));

export function relativeTime(value: string | number | Date): string {
  const delta = Date.now() - new Date(value).getTime();
  if (delta < 1_000) return "just now";
  if (delta < 60_000) return `${Math.floor(delta / 1_000)}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return `${Math.floor(delta / 86_400_000)}d ago`;
}

export const label = (name?: string) =>
  (name ?? "")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase()) || "Unknown";

export function percent(value: unknown, digits = 1): string {
  const number = Number(value);
  return Number.isFinite(number) ? `${(number * 100).toFixed(digits)}%` : "—";
}

export function milliseconds(value: unknown, digits = 2): string {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? `${number.toFixed(digits)} ms` : "—";
}

export function compactNumber(value: number): string {
  if (!Number.isFinite(value)) return "0";
  if (Math.abs(value) >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (Math.abs(value) >= 10_000) return `${(value / 1_000).toFixed(1)}k`;
  return String(Math.round(value));
}

export function bytes(value?: number | null): string {
  if (!value || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  let size = value;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
  return `${size.toFixed(size >= 100 || index === 0 ? 0 : 1)} ${units[index]}`;
}

export function shortId(value?: string, size = 12): string {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}

export const asRecord = (value: unknown): JsonRecord | undefined =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : undefined;

export function parseJson(value?: string): JsonRecord {
  if (!value) return {};
  try {
    return asRecord(JSON.parse(value)) ?? {};
  } catch {
    return {};
  }
}

export function pick<T>(record: JsonRecord | undefined, ...keys: string[]): T | undefined {
  for (const key of keys) if (record?.[key] !== undefined && record[key] !== null) return record[key] as T;
  return undefined;
}

export function scalar(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
  }
  return String(value);
}

/* ------------------------------------------------------------------ *
 * Domain semantics
 * ------------------------------------------------------------------ */

export function statusTone(value?: string): Tone {
  const normalized = (value ?? "").toUpperCase();
  if (["BLOCK", "DOWN", "DEGRADED", "FAILED", "UNAVAILABLE", "FALSE_POSITIVE", "EMERGENCY", "RETIRED", "TEMPORARY_BLOCK"].includes(normalized)) return "danger";
  if (["ACTIVE", "UP", "OK", "READY", "NORMAL", "ALLOW", "BENIGN", "CONFIRMED_ATTACK", "APPROVED", "SYNCHRONIZED", "ENABLED"].includes(normalized)) return "success";
  if (["ELEVATED", "RATE_LIMIT", "CHALLENGER", "CANDIDATE", "PENDING", "SHADOW", "WRONG_ATTACK_TYPE", "SKIPPED", "ESCALATION_REVISED"].includes(normalized)) return "warning";
  if (normalized === "ESCALATION_CONFIRMED") return "success";
  if (["TRAINING", "REGISTER", "EVALUATE_CHALLENGER"].includes(normalized)) return "info";
  return "neutral";
}

export function riskTone(risk: number): Tone {
  if (risk >= 0.81) return "danger";
  if (risk >= 0.5) return "warning";
  if (risk >= 0.2) return "info";
  return "success";
}

export const BENIGN_LABELS = new Set(["BENIGN", "UNAVAILABLE", "SKIPPED", "UNEVALUATED", "UNKNOWN", ""]);

export function isDetection(event: EventRecord): boolean {
  if (event.action === "BLOCK" || event.action === "RATE_LIMIT" || event.action === "TEMPORARY_BLOCK") return true;
  return !BENIGN_LABELS.has((event.predictedAttack ?? "").toUpperCase());
}

/** Deterministic palette so a given attack class or stage keeps the same colour in every chart. */
const PALETTE = ["#3b82f6", "#ff5c5c", "#f5a524", "#2bd576", "#a855f7", "#22d3ee", "#ec4899", "#84cc16", "#f97316", "#6366f1"];

const FIXED_COLORS: Record<string, string> = {
  BENIGN: "#2bd576",
  ALLOW: "#2bd576",
  BLOCK: "#ff5c5c",
  RATE_LIMIT: "#f5a524",
  TEMPORARY_BLOCK: "#f97316",
  SQL_INJECTION: "#ff5c5c",
  XSS: "#a855f7",
  COOKIE_INJECTION: "#f5a524",
  DIRECTORY_TRAVERSAL: "#22d3ee",
  REMOTE_CODE_EXECUTION: "#ec4899",
  UNAVAILABLE: "#4a4a4a",
  SKIPPED: "#6e6e6e",
  UNKNOWN: "#4a4a4a",
  TRIAGE: "#3b82f6",
  ROUTER: "#a855f7",
  INJECTION: "#ff5c5c",
  EXECUTION: "#f5a524",
  DEEP: "#22d3ee",
  NETWORK: "#2bd576",
  ESCALATION_REVISED: "#f97316",
  ESCALATION_CONFIRMED: "#2bd576",
  BRUTE_FORCE: "#f5a524",
  DOS_DDOS: "#ff5c5c",
  BOT_ANOMALY: "#a855f7"
};

export function colorFor(key: string, index = 0): string {
  const normalized = key.toUpperCase().replace(/[\s-]/g, "_");
  if (FIXED_COLORS[normalized]) return FIXED_COLORS[normalized];
  for (const [name, color] of Object.entries(FIXED_COLORS)) {
    if (normalized.startsWith(name)) return color;
  }
  let hash = index;
  for (let position = 0; position < key.length; position += 1) hash = (hash * 31 + key.charCodeAt(position)) >>> 0;
  return PALETTE[hash % PALETTE.length];
}

export function toneColor(tone: Tone): string {
  return { neutral: "#6e6e6e", success: "#2bd576", warning: "#f5a524", danger: "#ff5c5c", info: "#3b82f6", violet: "#a855f7" }[tone];
}

/** Human wording for each mitigation constant published by the gateway. */
export const MITIGATION_COPY: Record<string, string> = {
  BLOCKED_AT_GATEWAY: "Request rejected at the gateway with 403 before reaching the upstream",
  FORWARDED_TO_UPSTREAM: "Risk stayed under the policy threshold, so the request was proxied to the upstream",
  FORWARDED_PENDING_DEEP_ESCALATION: "Allowed provisionally on the fast verdict while the deep model adjudicates in the background",
  DEEP_ESCALATION_REVISED_AFTER_ALLOW: "The deep model disagreed with the fast verdict after the request had already been allowed",
  DEEP_ESCALATION_CONFIRMED_ALLOW: "The deep model confirmed the fast verdict for a request that was allowed provisionally",
  RATE_LIMITED_AT_GATEWAY: "Short-window request budget exhausted; answered with 429",
  TEMPORARY_BLOCK_ACTIVE: "Source is inside an active behavioural block window",
  INFERENCE_SKIPPED_UNDER_LOAD: "Load shedding skipped model inference and forwarded the request",
  FAIL_OPEN_DETECTION_UNAVAILABLE: "Detection service was unreachable; the gateway failed open and forwarded"
};

export const STAGE_COPY: Record<string, { title: string; description: string }> = {
  feature_extraction: { title: "Feature extraction", description: "Canonicalises the request and computes classical features" },
  triage: { title: "Triage", description: "Binary screen separating benign-like traffic from suspicious traffic" },
  router: { title: "Router", description: "Selects which expert families evaluate the request" },
  injection_expert: { title: "Injection expert", description: "SQL injection, cross-site scripting, and cookie injection" },
  execution_expert: { title: "Execution expert", description: "Directory traversal and remote code execution" },
  deep: { title: "Deep escalation", description: "Transformer adjudication for low-confidence expert output" }
};

export function sortedEntries(counts: Record<string, number>): [string, number][] {
  return Object.entries(counts).sort(([, first], [, second]) => second - first);
}
