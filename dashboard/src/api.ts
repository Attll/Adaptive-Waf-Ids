export type EventRecord = {
  id: number;
  eventId: string;
  occurredAt: string;
  category: string;
  requestId?: string;
  sourceHash?: string;
  method?: string;
  path?: string;
  statusCode: number;
  action?: string;
  predictedAttack?: string;
  risk: number;
  detailsJson: string;
};

export type Policy = { applicationId: string; version: number; blockRiskThreshold: number; rateLimitShortWindow: number };
export type Model = { modelVersionId: string; modelName: string; artifactVersion: string; status: string; metricsJson: string };
export type Application = { applicationId: string; name: string; upstreamUrl: string; enabled: boolean };
export type Audit = { auditId: string; administrator: string; occurredAt: string; entityType: string; entityId: string; action: string; oldValueJson?: string; newValueJson?: string };
export type GatewayMode = { mode: string };
export type GatewayPolicy = { version: number; rateLimitShortWindow: number; blockRiskThreshold: number };
export type Health = { status: string; components?: Record<string, { status: string }> };
export type NetworkEvidence = { source_ip: string; destination_ip?: string; network_risk: number; network_class?: string; confidence?: number; model_version: string; observed_at: string };
export type TrainingRun = { externalRunId: string; modelName: string; datasetVersion: string; status: string; shadowMode: boolean; artifactUri?: string; metricsJson: string; driftJson: string; startedAt: string; completedAt?: string };

export class ApiError extends Error {
  constructor(message: string, public readonly status?: number) { super(message); }
}

export async function recentNetworkEvidence(): Promise<{ events: NetworkEvidence[]; model_version: string }> {
  const response = await fetch("/sensor-api/v1/network/recent");
  if (!response.ok) throw new ApiError(`Network sensor returned ${response.status}`, response.status);
  return response.json() as Promise<{ events: NetworkEvidence[]; model_version: string }>;
}

export class DashboardApi {
  constructor(private readonly username: string, private readonly password: string) { }

  private async control<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Authorization", `Basic ${btoa(`${this.username}:${this.password}`)}`);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(`/control-api${path}`, { ...options, headers });
    if (!response.ok) throw new ApiError(await response.text() || `Control API returned ${response.status}`, response.status);
    return response.status === 204 ? (undefined as T) : response.json() as Promise<T>;
  }

  async snapshot() {
    const [policy, events, models, applications, audit, controlHealth, mode, gatewayPolicy] = await Promise.all([
      this.control<Policy>("/v1/control/policy"),
      this.control<{ events: EventRecord[] }>("/v1/security/events?limit=100"),
      this.control<{ models: Model[] }>("/v1/control/models"),
      this.control<{ applications: Application[] }>("/v1/control/applications"),
      this.control<{ audit: Audit[] }>("/v1/control/audit?limit=100"),
      fetch("/control-api/actuator/health").then((response) => response.json() as Promise<Health>),
      fetch("/gateway-api/actuator/waf/mode").then((response) => response.json() as Promise<GatewayMode>),
      fetch("/gateway-api/actuator/waf/policy").then((response) => response.json() as Promise<GatewayPolicy>)
    ]);
    return { policy, events: events.events, models: models.models, applications: applications.applications, audit: audit.audit, controlHealth, mode, gatewayPolicy };
  }

  updatePolicy(policy: Pick<Policy, "blockRiskThreshold" | "rateLimitShortWindow">) {
    return this.control<Policy>("/v1/control/policy", { method: "PUT", body: JSON.stringify(policy) });
  }
  block(sourceIp: string, reason: string, duration = "PT1H") {
    return this.control("/v1/control/blocks", { method: "POST", body: JSON.stringify({ sourceIp, reason, duration }) });
  }
  unblock(sourceIp: string) { return this.control<void>(`/v1/control/blocks/${encodeURIComponent(sourceIp)}`, { method: "DELETE" }); }
  promote(id: string) { return this.control<void>(`/v1/control/models/${id}/promote`, { method: "POST" }); }
  assign(id: string) { return this.control<void>(`/v1/control/models/${id}/assign`, { method: "POST" }); }
  submitFeedback(eventId: string, verdict: string, notes: string, correctAttackType?: string) {
    return this.control("/v1/control/feedback", { method: "POST", body: JSON.stringify({ eventId, verdict, notes, correctAttackType }) });
  }
  trainingRuns() { return this.control<{ runs: TrainingRun[] }>("/v1/control/training-runs"); }
}
