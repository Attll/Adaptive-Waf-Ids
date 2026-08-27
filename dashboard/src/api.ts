export type EventRecord = {
  id: number;
  eventId: string;
  occurredAt: string;
  category: string;
  requestId?: string;
  sourceIp?: string;
  method?: string;
  path?: string;
  query?: string;
  statusCode: number;
  action?: string;
  predictedAttack?: string;
  risk: number;
  mitigation?: string;
  mode?: string;
  userAgent?: string;
  upstream?: string;
  detectionLatencyMs: number;
  upstreamLatencyMs: number;
  gatewayLatencyMs: number;
  routingPath?: string;
  deepModelUsed: boolean;
  triageDecision?: string;
  confidence: number;
  detailsJson: string;
};

export type Policy = { applicationId: string; version: number; blockRiskThreshold: number; rateLimitShortWindow: number };
export type Model = { modelVersionId: string; modelName: string; artifactVersion: string; status: string; metricsJson: string };
export type Application = { applicationId: string; name: string; upstreamUrl: string; enabled: boolean };
export type BlockedEntity = { sourceIp: string; reason: string; expiresAt: string; active: boolean };
export type Audit = { auditId: string; administrator: string; occurredAt: string; entityType: string; entityId: string; action: string; oldValueJson?: string; newValueJson?: string };
export type GatewayMode = { mode: string };
export type GatewayPolicy = { version: number; rateLimitShortWindow: number; blockRiskThreshold: number };
export type Health = { status: string; components?: Record<string, { status: string }> };
export type SensorHealth = Health & { redis?: string; model_version?: string };
export type RuntimeModels = { models: Record<string, string> };
export type NetworkEvidence = { source_ip: string; destination_ip?: string; network_risk: number; network_class?: string; confidence?: number; model_version: string; observed_at: string };
export type TrainingRun = { externalRunId: string; modelName: string; datasetVersion: string; status: string; shadowMode: boolean; artifactUri?: string; metricsJson: string; driftJson: string; startedAt: string; completedAt?: string };
export type FeedbackRecord = { feedbackId: string; eventId: string; verdict: string; correctAttackType?: string; notes?: string; submittedBy: string; submittedAt: string; method?: string; path?: string; predictedAttack?: string };

export type TimelinePoint = { bucket: string; total: number; detections: number; blocked: number };
export type SourceProfile = {
  sourceIp: string;
  requests: number;
  detections: number;
  blocked: number;
  maxRisk: number;
  meanLatencyMs: number;
  lastSeen?: string;
  attacks: Record<string, number>;
  endpoints: Record<string, number>;
};

export type Statistics = {
  summary: {
    total: number;
    detections: number;
    blocked: number;
    rateLimited: number;
    deepEscalations: number;
    uniqueSources: number;
    latencyP50Ms: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
    detectionLatencyMeanMs: number;
    upstreamLatencyMeanMs: number;
  };
  byAttack: Record<string, number>;
  byAction: Record<string, number>;
  byMitigation: Record<string, number>;
  byEndpoint: Record<string, number>;
  bySource: Record<string, number>;
  byRoute: Record<string, number>;
  byStatus: Record<string, number>;
  timeline: TimelinePoint[];
  sources: SourceProfile[];
};

export type AlgorithmProfile = { family: string; description: string };

export type CatalogCandidate = {
  algorithm: string;
  deployed: boolean;
  model_size_bytes?: number | null;
  metrics: Record<string, number>;
  confusion_matrix?: number[][] | null;
  hyperparameters: Record<string, unknown>;
  profile: AlgorithmProfile;
};

export type CatalogStage = {
  stage: string;
  title: string;
  plane: string;
  purpose: string;
  labels: string[];
  defends_against: string[];
  training: { dataset_version?: string; feature_version?: string; evaluated_algorithms: string[] };
  deployment: {
    run_id: string;
    algorithm: string;
    artifact: string;
    dataset_version?: string;
    feature_version?: string;
    calibration?: string | null;
    model_version: string;
    device?: string | null;
    router_thresholds?: { minimum_top1_probability?: number; minimum_top1_margin?: number } | null;
    profile: AlgorithmProfile;
    hyperparameters: Record<string, unknown>;
  };
  candidates: CatalogCandidate[];
};

export type ModelCatalog = {
  generated_at: string;
  pipeline: {
    name: string;
    thresholds: Record<string, unknown>;
    fusion: Record<string, unknown>;
    calibration_run?: string;
    stage_order: string[];
  };
  stages: CatalogStage[];
  ensembles: { family: string; run_id: string; combinations: { members: string[]; retained: boolean; metrics: Record<string, number> }[] }[];
  benchmark: { summary: Record<string, unknown>; runs: { run_id: string; metrics: Record<string, unknown> }[] };
  runtime: Record<string, string>;
};

export type DetectionEvidence = {
  request_id: string;
  timestamp: string;
  triage: { decision: string; suspicious_probability: number };
  router: { scores: Record<string, number>; selected_experts: string[] } | null;
  expert_outputs: { predicted_attack: string; confidence: number; risk: number; model_version: string; class_scores: Record<string, number> }[];
  deep_output: { predicted_attack: string; confidence: number; risk: number; model_version: string; class_scores: Record<string, number> } | null;
  ensemble_used: boolean;
  deep_model_used: boolean;
  predicted_attack: string;
  risks: { http: number; behaviour: number; network: number; overall: number };
  routing_path: string[];
  latency_by_stage_ms: Record<string, number>;
  total_latency_ms: number;
  model_versions: Record<string, string>;
  explanation_evidence: Record<string, string>;
};

export type BatchProbe = {
  label: string;
  method: string;
  path: string;
  query?: string;
  body?: string;
  expected: string;
};

export type BatchResult = {
  index: number;
  expected?: string | null;
  request: { method: string; path: string; query?: string; body?: string };
  detection?: DetectionEvidence;
  service_inference_ms?: number;
  matched?: boolean | null;
  error?: string;
};

export type BatchResponse = {
  results: BatchResult[];
  summary: {
    submitted: number;
    evaluated: number;
    failed: number;
    matched: number;
    scored: number;
    accuracy: number | null;
    deep_escalations: number;
    mean_risk: number;
    latency_p50_ms: number;
    latency_p95_ms: number;
    total_latency_ms: number;
    routes: Record<string, number>;
    attacks: Record<string, number>;
  };
};

export type GatewayProbeResult = {
  label: string;
  method: string;
  target: string;
  status: number;
  blocked: boolean;
  predictedAttack?: string;
  roundTripMs: number;
  requestId?: string;
  bodyPreview: string;
  error?: string;
};

export type EscalationOutcome = {
  escalation_id: string;
  request_id: string;
  method: string;
  path: string;
  query: string;
  source_ip?: string | null;
  submitted_at: string;
  resolved_at: string;
  queued_ms: number;
  deep_latency_ms: number;
  provisional: { predicted_attack: string; risk: number; confidence: number };
  revised: { predicted_attack: string; risk: number; confidence: number; model_version: string; class_scores: Record<string, number> };
  changed: boolean;
  error?: string | null;
};

export type EscalationStatistics = {
  enabled: boolean;
  workers: number;
  queue_depth: number;
  queue_limit: number;
  submitted: number;
  resolved: number;
  failed: number;
  rejected: number;
  retained: number;
  verdict_changed: number;
  mean_queued_ms: number;
  median_deep_latency_ms: number;
};

export type RedisNamespace = { pattern: string; count: number; sample: { key: string; ttlSeconds: number; type: string }[] };

export type Infrastructure = {
  redis: {
    reachable: boolean;
    ping?: string;
    pingLatencyMs?: number;
    error?: string;
    namespaces: Record<string, RedisNamespace>;
    totalTrackedKeys: number;
  };
  database: {
    reachable: boolean;
    error?: string;
    queryLatencyMs?: number;
    totalEvents?: number;
    escalationRecords?: number;
    newestEventAt?: string | null;
    secondsSinceNewestEvent?: number | null;
    tableCounts?: Record<string, number>;
    jdbcUrl?: string;
    externalJdbcUrl?: string;
    username?: string;
  };
};

export type CorpusSummary = {
  http: { available: boolean; records: number; labels: Record<string, number>; source: string };
  network: { available: boolean; records: number; labels: Record<string, number>; source: string };
};

export type HttpCorpusRecord = { label: string; method: string; path: string; query: string; body: string; cookies: Record<string, string> };
export type NetworkCorpusRecord = { label: string; features: Record<string, number> };

export type DashboardSnapshot = {
  policy: Policy;
  events: EventRecord[];
  statistics: Statistics;
  models: Model[];
  applications: Application[];
  blocks: BlockedEntity[];
  audit: Audit[];
  feedback: FeedbackRecord[];
  trainingRuns: TrainingRun[];
  controlHealth: Health;
  gatewayHealth: Health;
  detectionHealth: Health;
  detectionReady: Health;
  adaptationHealth: Health;
  sensorHealth: SensorHealth;
  runtimeModels: RuntimeModels;
  mode: GatewayMode;
  gatewayPolicy: GatewayPolicy;
};

export class ApiError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
  }
}

const EMPTY_STATISTICS: Statistics = {
  summary: {
    total: 0, detections: 0, blocked: 0, rateLimited: 0, deepEscalations: 0, uniqueSources: 0,
    latencyP50Ms: 0, latencyP95Ms: 0, latencyP99Ms: 0, detectionLatencyMeanMs: 0, upstreamLatencyMeanMs: 0
  },
  byAttack: {}, byAction: {}, byMitigation: {}, byEndpoint: {}, bySource: {}, byRoute: {}, byStatus: {},
  timeline: [], sources: []
};

const EMPTY_HEALTH: Health = { status: "UNAVAILABLE" };

async function publicJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) throw new ApiError(`${path} returned ${response.status}`, response.status);
  return response.json() as Promise<T>;
}

/** Optional dependencies must never break the console: an unreachable service degrades to a placeholder. */
async function optional<T>(loader: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await loader();
  } catch {
    return fallback;
  }
}

export async function recentNetworkEvidence(): Promise<{ events: NetworkEvidence[]; model_version: string }> {
  return publicJson("/sensor-api/v1/network/recent");
}

export async function modelCatalog(): Promise<ModelCatalog> {
  return publicJson<ModelCatalog>("/detection-api/v1/models/catalog");
}

export async function corpusSummary(): Promise<CorpusSummary> {
  return publicJson<CorpusSummary>("/detection-api/v1/corpus");
}

export async function sampleHttpCorpus(count: number, labels: string[], seed?: number): Promise<{ samples: HttpCorpusRecord[]; source: string }> {
  const search = new URLSearchParams({ count: String(count) });
  if (labels.length) search.set("labels", labels.join(","));
  if (seed !== undefined) search.set("seed", String(seed));
  return publicJson(`/detection-api/v1/corpus/http?${search}`);
}

export async function sampleNetworkCorpus(count: number, labels: string[], seed?: number): Promise<{ samples: NetworkCorpusRecord[]; source: string }> {
  const search = new URLSearchParams({ count: String(count) });
  if (labels.length) search.set("labels", labels.join(","));
  if (seed !== undefined) search.set("seed", String(seed));
  return publicJson(`/detection-api/v1/corpus/network?${search}`);
}

export async function escalations(limit = 50): Promise<{ escalations: EscalationOutcome[]; statistics: EscalationStatistics }> {
  return publicJson(`/detection-api/v1/escalations?limit=${limit}`);
}

/** Submits one classified flow to the network sensor, which writes its risk context into Redis for the gateway. */
export async function deployNetworkFlow(sourceIp: string, destinationIp: string, features: Record<string, number>): Promise<{ ok: boolean; networkClass?: string; risk?: number; confidence?: number; latencyMs: number; error?: string }> {
  const started = performance.now();
  try {
    const response = await fetch("/sensor-api/v1/flows", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_ip: sourceIp, destination_ip: destinationIp, features })
    });
    const latencyMs = performance.now() - started;
    if (!response.ok) {
      return { ok: false, latencyMs, error: `sensor returned ${response.status}` };
    }
    const body = await response.json();
    const context = body.network_context ?? {};
    return {
      ok: true,
      latencyMs,
      networkClass: context.network_class,
      risk: context.network_risk,
      confidence: context.confidence
    };
  } catch (error) {
    return { ok: false, latencyMs: performance.now() - started, error: error instanceof Error ? error.message : "sensor unreachable" };
  }
}

export async function detectBatch(probes: BatchProbe[]): Promise<BatchResponse> {
  const response = await fetch("/detection-api/v1/detect/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      requests: probes.map((probe) => ({
        method: probe.method,
        path: probe.path,
        query: probe.query ?? "",
        body: probe.body ?? "",
        headers: { "content-type": "application/json" }
      })),
      labels: probes.map((probe) => probe.expected)
    })
  });
  if (!response.ok) throw new ApiError(await response.text() || `Detection service returned ${response.status}`, response.status);
  return response.json() as Promise<BatchResponse>;
}

/** Replays a probe through the gateway so the whole chain — enforcement, upstream, journal — is exercised. */
export async function probeGateway(probe: BatchProbe): Promise<GatewayProbeResult> {
  const target = `/gateway-api/backend${probe.path}${probe.query ? `?${probe.query}` : ""}`;
  const started = performance.now();
  try {
    const response = await fetch(target, {
      method: probe.method,
      headers: probe.body ? { "Content-Type": "application/json" } : undefined,
      body: probe.body || undefined
    });
    const text = await response.text();
    let predictedAttack: string | undefined;
    try {
      predictedAttack = JSON.parse(text)?.error?.predicted_attack;
    } catch {
      predictedAttack = undefined;
    }
    return {
      label: probe.label,
      method: probe.method,
      target: `${probe.path}${probe.query ? `?${probe.query}` : ""}`,
      status: response.status,
      blocked: response.status === 403 || response.status === 429,
      predictedAttack,
      roundTripMs: performance.now() - started,
      requestId: response.headers.get("x-request-id") ?? undefined,
      bodyPreview: text.slice(0, 400)
    };
  } catch (error) {
    return {
      label: probe.label,
      method: probe.method,
      target: `${probe.path}${probe.query ? `?${probe.query}` : ""}`,
      status: 0,
      blocked: false,
      roundTripMs: performance.now() - started,
      bodyPreview: "",
      error: error instanceof Error ? error.message : "request failed"
    };
  }
}

export class DashboardApi {
  constructor(private readonly username: string, private readonly password: string) { }

  private async control<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Authorization", `Basic ${btoa(`${this.username}:${this.password}`)}`);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(`/control-api${path}`, { ...options, headers });
    if (!response.ok) throw new ApiError(await response.text() || `Control API returned ${response.status}`, response.status);
    const body = await response.text();
    return body ? JSON.parse(body) as T : (undefined as T);
  }

  /** The control plane is required; every other service degrades gracefully so one outage cannot lock the console. */
  async snapshot(): Promise<DashboardSnapshot> {
    const [policy, events, statistics, models, applications, blocks, audit, feedback, trainingRuns] = await Promise.all([
      this.control<Policy>("/v1/control/policy"),
      this.control<{ events: EventRecord[] }>("/v1/security/events?limit=300"),
      this.control<Statistics>("/v1/security/statistics?limit=500"),
      this.control<{ models: Model[] }>("/v1/control/models"),
      this.control<{ applications: Application[] }>("/v1/control/applications"),
      this.control<{ blocks: BlockedEntity[] }>("/v1/control/blocks"),
      this.control<{ audit: Audit[] }>("/v1/control/audit?limit=100"),
      this.control<{ feedback: FeedbackRecord[] }>("/v1/control/feedback"),
      this.control<{ runs: TrainingRun[] }>("/v1/control/training-runs")
    ]);
    const [controlHealth, gatewayHealth, detectionHealth, detectionReady, adaptationHealth, sensorHealth, runtimeModels, mode, gatewayPolicy] = await Promise.all([
      optional(() => publicJson<Health>("/control-api/actuator/health"), EMPTY_HEALTH),
      optional(() => publicJson<Health>("/gateway-api/actuator/health"), EMPTY_HEALTH),
      optional(() => publicJson<Health>("/detection-api/health"), EMPTY_HEALTH),
      optional(() => publicJson<Health>("/detection-api/ready"), EMPTY_HEALTH),
      optional(() => publicJson<Health>("/adaptation-api/health"), EMPTY_HEALTH),
      optional(() => publicJson<SensorHealth>("/sensor-api/health"), EMPTY_HEALTH as SensorHealth),
      optional(() => publicJson<RuntimeModels>("/detection-api/v1/models"), { models: {} }),
      optional(() => publicJson<GatewayMode>("/gateway-api/actuator/waf/mode"), { mode: "UNAVAILABLE" }),
      optional(() => publicJson<GatewayPolicy>("/gateway-api/actuator/waf/policy"), { version: 0, blockRiskThreshold: 0, rateLimitShortWindow: 0 })
    ]);
    return {
      policy,
      events: events.events ?? [],
      statistics: statistics ?? EMPTY_STATISTICS,
      models: models.models ?? [],
      applications: applications.applications ?? [],
      blocks: blocks.blocks ?? [],
      audit: audit.audit ?? [],
      feedback: feedback.feedback ?? [],
      trainingRuns: trainingRuns.runs ?? [],
      controlHealth, gatewayHealth, detectionHealth, detectionReady, adaptationHealth, sensorHealth,
      runtimeModels, mode, gatewayPolicy
    };
  }

  events(query: Record<string, string | number | boolean | undefined>) {
    const search = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => value !== undefined && search.set(key, String(value)));
    return this.control<{ events: EventRecord[]; count: number; subscribers: number }>(`/v1/security/events?${search}`);
  }

  statistics(limit = 500) {
    return this.control<Statistics>(`/v1/security/statistics?limit=${limit}`);
  }

  infrastructure() {
    return this.control<Infrastructure>("/v1/control/infrastructure");
  }

  journalledEscalations(limit = 50) {
    return this.control<{ escalations: Record<string, unknown>[]; retained: number }>(`/v1/security/escalations?limit=${limit}`);
  }

  streamTicket() {
    return this.control<{ ticket: string; expiresAt: string; path: string }>("/v1/security/stream-ticket");
  }

  updatePolicy(policy: Pick<Policy, "blockRiskThreshold" | "rateLimitShortWindow">) {
    return this.control<Policy>("/v1/control/policy", { method: "PUT", body: JSON.stringify(policy) });
  }
  block(sourceIp: string, reason: string, duration = "PT1H") {
    return this.control<BlockedEntity>("/v1/control/blocks", { method: "POST", body: JSON.stringify({ sourceIp, reason, duration }) });
  }
  unblock(sourceIp: string) { return this.control<void>(`/v1/control/blocks/${encodeURIComponent(sourceIp)}`, { method: "DELETE" }); }
  promote(id: string) { return this.control<void>(`/v1/control/models/${id}/promote`, { method: "POST" }); }
  assign(id: string) { return this.control<void>(`/v1/control/models/${id}/assign`, { method: "POST" }); }
  approve(id: string) { return this.control<void>(`/v1/control/models/${id}/approve`, { method: "POST" }); }
  retire(id: string) { return this.control<void>(`/v1/control/models/${id}/retire`, { method: "POST" }); }
  createApplication(name: string, upstreamUrl: string) {
    return this.control<Application>("/v1/control/applications", { method: "POST", body: JSON.stringify({ name, upstreamUrl }) });
  }
  setApplicationEnabled(applicationId: string, enabled: boolean) {
    return this.control<Application>(`/v1/control/applications/${applicationId}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
  }
  submitFeedback(eventId: string, verdict: string, notes: string, correctAttackType?: string) {
    return this.control("/v1/control/feedback", { method: "POST", body: JSON.stringify({ eventId, verdict, notes, correctAttackType }) });
  }
}

export function streamUrl(ticket: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/control-ws/v1/stream/events?ticket=${encodeURIComponent(ticket)}`;
}
