import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  ApiError,
  DashboardApi,
  recentNetworkEvidence,
  type Audit,
  type DashboardSnapshot,
  type EventRecord,
  type FeedbackRecord,
  type Health,
  type Model,
  type NetworkEvidence,
  type TrainingRun
} from "./api";

type Section =
  | "Overview"
  | "Requests"
  | "Detections"
  | "Request Inspector"
  | "Models"
  | "Training Runs"
  | "Policy"
  | "IP Controls"
  | "Network IDS"
  | "Applications"
  | "Feedback"
  | "Service Health"
  | "Audit Log"
  | "Settings";

type Credentials = { username: string; password: string };
type JsonRecord = Record<string, unknown>;
type ViewProps = {
  snapshot: DashboardSnapshot;
  selected?: EventRecord;
  setSelected: (event: EventRecord) => void;
  api: DashboardApi;
  mutate: (action: () => Promise<unknown>, success: string) => Promise<void>;
  username: string;
  setSection: (section: Section) => void;
  signOut: () => void;
};

const navGroups: [string, Section[]][] = [
  ["Observe", ["Overview", "Requests", "Detections", "Request Inspector"]],
  ["Lifecycle", ["Models", "Training Runs"]],
  ["Enforce", ["Policy", "IP Controls", "Network IDS", "Applications"]],
  ["Operate", ["Feedback", "Service Health", "Audit Log", "Settings"]]
];

const sectionDescription: Record<Section, string> = {
  Overview: "Current protection posture across the gateway and control plane",
  Requests: "Sanitized request decisions persisted by the control service",
  Detections: "Non-benign classifications and blocked request decisions",
  "Request Inspector": "Decision evidence retained for one persisted request",
  Models: "Loaded inference artifacts and governed lifecycle versions",
  "Training Runs": "Candidate evaluation and shadow-run history",
  Policy: "Authoritative policy and the gateway's applied cache",
  "IP Controls": "Manual source-address enforcement",
  "Network IDS": "Asynchronous flow classifications from the network sensor",
  Applications: "Services registered for gateway protection",
  Feedback: "Administrator verdicts used by the adaptation workflow",
  "Service Health": "Readiness of every dashboard-connected service",
  "Audit Log": "Human-readable record of administrative changes",
  Settings: "Operator session and local service connections"
};

const fmt = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  month: "short",
  day: "numeric"
});

const label = (name: string) => name.replaceAll("_", " ").replaceAll("-", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
const statusTone = (value?: string) => {
  const normalized = value?.toUpperCase();
  if (["BLOCK", "DOWN", "DEGRADED", "FAILED", "UNAVAILABLE", "FALSE_POSITIVE"].includes(normalized ?? "")) return "danger";
  if (["ACTIVE", "UP", "OK", "READY", "NORMAL", "ALLOW", "BENIGN", "CONFIRMED_ATTACK"].includes(normalized ?? "")) return "success";
  return "warning";
};
const healthStatus = (health: Health) => ["UP", "OK", "READY"].includes(health.status.toUpperCase()) ? "UP" : health.status.toUpperCase();
const asRecord = (value: unknown): JsonRecord | undefined => value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : undefined;
const parseJson = (value?: string): JsonRecord => {
  if (!value) return {};
  try { return asRecord(JSON.parse(value)) ?? {}; } catch { return {}; }
};
const eventDetails = (event?: EventRecord) => parseJson(event?.detailsJson);
const pick = <T,>(record: JsonRecord | undefined, ...keys: string[]): T | undefined => {
  for (const key of keys) if (record?.[key] !== undefined) return record[key] as T;
  return undefined;
};
const scalar = (value: unknown): string => {
  if (value === null || value === undefined || value === "") return "Not recorded";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
  return String(value);
};

export function App() {
  const [section, setSection] = useState<Section>("Overview");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [credentials, setCredentials] = useState<Credentials>();
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>();
  const [selected, setSelected] = useState<EventRecord>();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("Connected to the security platform.");
  const [loginError, setLoginError] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date>();

  const api = useMemo(() => credentials ? new DashboardApi(credentials.username, credentials.password) : undefined, [credentials]);
  const applySnapshot = useCallback((next: DashboardSnapshot) => {
    setSnapshot(next);
    setSelected((current) => next.events.find((event) => event.eventId === current?.eventId) ?? next.events[0]);
    setLastRefresh(new Date());
  }, []);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setLoginError("");
    try {
      const candidate = new DashboardApi(username.trim(), password);
      const next = await candidate.snapshot();
      setCredentials({ username: username.trim(), password });
      applySnapshot(next);
      setMessage("Connected to the security platform.");
    } catch (error) {
      setLoginError(error instanceof ApiError && error.status === 401
        ? "The username or password is incorrect."
        : `The security console is unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
    } finally { setLoading(false); }
  };

  const refresh = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    try {
      applySnapshot(await api.snapshot());
      setMessage("Live service data refreshed.");
    } catch (error) {
      setMessage(error instanceof ApiError && error.status === 401
        ? "Your administrator session is no longer authorized."
        : `Unable to refresh live data: ${error instanceof Error ? error.message : "unknown error"}`);
    } finally { setLoading(false); }
  }, [api, applySnapshot]);

  useEffect(() => {
    if (!api) return;
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [api, refresh]);

  const mutate = async (action: () => Promise<unknown>, success: string) => {
    try { await action(); setMessage(success); await refresh(); }
    catch (error) { setMessage(`Action failed: ${error instanceof Error ? error.message : "unknown error"}`); }
  };

  const signOut = () => {
    setCredentials(undefined);
    setSnapshot(undefined);
    setSelected(undefined);
    setPassword("");
    setSection("Overview");
    setLoginError("");
  };

  if (!credentials || !snapshot || !api) {
    return <SignIn username={username} password={password} loading={loading} error={loginError} onUsername={setUsername} onPassword={setPassword} onSubmit={signIn} onDemoCredentials={() => { setUsername("admin"); setPassword("adaptive_waf_dev"); setLoginError(""); }} />;
  }

  const props: ViewProps = { snapshot, selected, setSelected, api, mutate, username: credentials.username, setSection, signOut };
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="environment-switcher"><span className="environment-icon">P</span><div><strong>Production</strong><small>Security workspace</small></div><span className="chevron">⌄</span></div>
      <nav>{navGroups.map(([group, entries]) => <div className="nav-group" key={group}><p>{group}</p>{entries.map((entry) => <button key={entry} className={section === entry ? "nav-item active" : "nav-item"} onClick={() => setSection(entry)}>{entry}</button>)}</div>)}</nav>
      <div className="sidebar-footer"><span className={`dot ${statusTone(snapshot.mode.mode)}`} /><span>{label(snapshot.mode.mode)} protection</span><kbd>Live</kbd></div>
    </aside>
    <main className="workspace-main">
      <header className="topbar"><div className="breadcrumb"><span>Security</span><i>/</i><strong>{section}</strong></div><div className="top-actions"><span className="refresh-note">{lastRefresh ? `Updated ${fmt.format(lastRefresh)}` : "Connecting"}</span><button className="secondary" onClick={() => void refresh()} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</button><button className="user-chip" onClick={() => setSection("Settings")}><span>{credentials.username.slice(0, 1).toUpperCase()}</span>{credentials.username}</button></div></header>
      <div className="page-heading"><div><p>{sectionDescription[section]}</p><h1>{section}</h1></div><Badge value={snapshot.mode.mode} /></div>
      <div className="notice" role="status"><span className={`dot ${message.startsWith("Action failed") || message.startsWith("Unable") ? "danger" : "success"}`} />{message}</div>
      <section className="content">{renderSection(section, props)}</section>
    </main>
  </div>;
}

function SignIn({ username, password, loading, error, onUsername, onPassword, onSubmit, onDemoCredentials }: { username: string; password: string; loading: boolean; error: string; onUsername: (value: string) => void; onPassword: (value: string) => void; onSubmit: (event: FormEvent) => void; onDemoCredentials: () => void }) {
  return <main className="auth-shell"><div className="auth-grid" aria-hidden="true" /><section className="auth-card"><div className="auth-mark"><span /></div><p className="auth-kicker">Security operations</p><h1>Sign in to the console</h1><p className="auth-copy">Monitor application traffic, investigate detections, and manage enforcement from one workspace.</p><form onSubmit={onSubmit}><label>Username<input autoFocus autoComplete="username" value={username} onChange={(event) => onUsername(event.target.value)} placeholder="admin" /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} placeholder="Enter your password" /></label>{error && <div className="auth-error" role="alert"><span>!</span>{error}</div>}<button className="auth-submit" disabled={loading || !username.trim() || !password}>{loading ? "Connecting..." : "Continue"}</button></form><div className="demo-access"><div><strong>Running the local demo?</strong><span>Use the provisioned administrator account.</span></div><button type="button" className="text-button" onClick={onDemoCredentials}>Fill demo credentials</button></div></section><footer className="auth-footer"><span>Protected administrative surface</span><span>•</span><span>Local environment</span></footer></main>;
}

function renderSection(section: Section, props: ViewProps) {
  switch (section) {
    case "Overview": return <Overview {...props} />;
    case "Requests": return <Events {...props} detectionsOnly={false} />;
    case "Detections": return <Events {...props} detectionsOnly />;
    case "Request Inspector": return <Inspector {...props} />;
    case "Models": return <Models {...props} />;
    case "Training Runs": return <TrainingRuns runs={props.snapshot.trainingRuns} />;
    case "Policy": return <PolicyEditor {...props} />;
    case "IP Controls": return <IpManagement {...props} />;
    case "Network IDS": return <NetworkIds />;
    case "Applications": return <Applications {...props} />;
    case "Feedback": return <Feedback {...props} />;
    case "Service Health": return <HealthPanel {...props} />;
    case "Audit Log": return <AuditLog {...props} />;
    case "Settings": return <Settings {...props} />;
  }
}

function Overview({ snapshot, setSection }: ViewProps) {
  const events = snapshot.events;
  const blocked = events.filter((event) => event.action === "BLOCK").length;
  const attacks = events.filter(isDetection).length;
  const healthy = serviceRows(snapshot).filter((service) => service.status === "UP").length;
  return <div className="stack">
    <SourceStrip items={["Control plane: event journal + policy", "Gateway: mode + applied policy", "Detection: loaded models"]} />
    <div className="metrics-grid">
      <Metric title="Requests retained" value={String(events.length)} detail="Most recent control-plane window" tone="neutral" />
      <Metric title="Blocked" value={String(blocked)} detail={events.length ? `${Math.round((blocked / events.length) * 100)}% of retained requests` : "Awaiting traffic"} tone="danger" />
      <Metric title="Detections" value={String(attacks)} detail="Non-benign or blocked decisions" tone="warning" />
      <Metric title="Services ready" value={`${healthy}/${serviceRows(snapshot).length}`} detail={`Policy v${snapshot.gatewayPolicy.version} applied`} tone="success" />
    </div>
    <div className="two-columns">
      <Panel title="Recent request decisions" action={<button className="text-button" onClick={() => setSection("Requests")}>Open request log</button>}><EventTable events={events.slice(0, 7)} /></Panel>
      <Panel title="Protection posture"><dl className="kv-list"><KV k="Gateway mode" v={<Badge value={snapshot.mode.mode} />} /><KV k="Block threshold" v={`${(snapshot.gatewayPolicy.blockRiskThreshold * 100).toFixed(0)}% risk`} /><KV k="Short-window limit" v={`${snapshot.gatewayPolicy.rateLimitShortWindow} requests`} /><KV k="Runtime models" v={String(Object.keys(snapshot.runtimeModels.models).length)} /><KV k="Protected applications" v={String(snapshot.applications.filter((app) => app.enabled).length)} /></dl></Panel>
    </div>
    <Panel title="Platform readiness"><ServiceGrid snapshot={snapshot} compact /></Panel>
  </div>;
}

function Events({ snapshot, selected, setSelected, setSection, detectionsOnly }: ViewProps & { detectionsOnly: boolean }) {
  const [filter, setFilter] = useState("");
  const base = detectionsOnly ? snapshot.events.filter(isDetection) : snapshot.events;
  const events = base.filter((event) => `${event.path} ${event.method} ${event.predictedAttack} ${event.action} ${event.sourceHash}`.toLowerCase().includes(filter.toLowerCase()));
  return <div className="stack">
    <SourceStrip items={["Security control service", "GET /v1/security/events", "15 second refresh"]} />
    <div className="toolbar"><input aria-label="Filter requests" placeholder="Filter by path, method, classification, action, or source hash" value={filter} onChange={(event) => setFilter(event.target.value)} /><span>{events.length} persisted records</span></div>
    {detectionsOnly && <AttackBreakdown events={events} />}
    <Panel title={detectionsOnly ? "Detected threats" : "Request decision log"} action={selected && <button className="text-button" onClick={() => setSection("Request Inspector")}>Inspect selected request</button>}><EventTable events={events} selected={selected} onSelect={setSelected} /></Panel>
  </div>;
}

function Inspector({ selected, snapshot, mutate, api, setSelected }: ViewProps) {
  const details = eventDetails(selected);
  const detection = asRecord(details.detection) ?? details;
  const route = pick<string[]>(detection, "routingPath", "routing_path") ?? [];
  const latency = pick<Record<string, number>>(detection, "latencyByStageMs", "latency_by_stage_ms");
  const totalLatency = pick<number>(detection, "totalLatencyMs", "total_latency_ms");
  const hasDetailedEvidence = Boolean(detection.triage || detection.router || detection.expertOutputs || detection.expert_outputs || detection.deepOutput || detection.deep_output);
  return <div className="stack">
    <SourceStrip items={["Security control service", "GET /v1/security/events", "Sanitized evidence only"]} />
    <div className="split-layout">
      <Panel title="Recent requests"><EventTable events={snapshot.events} selected={selected} onSelect={setSelected} compact /></Panel>
      <div className="stack">
        <Panel title="Request decision" action={selected ? <Badge value={selected.action ?? "UNKNOWN"} /> : undefined}>{selected ? <div className="decision-grid"><KV k="Request" v={`${selected.method ?? "?"} ${selected.path ?? "/"}`} /><KV k="HTTP status" v={String(selected.statusCode)} /><KV k="Classification" v={label(selected.predictedAttack ?? "UNKNOWN")} /><KV k="Overall risk" v={`${(selected.risk * 100).toFixed(2)}%`} /><KV k="Request ID" v={selected.requestId ?? "Not recorded"} /><KV k="Source identity" v={shortId(selected.sourceHash)} /><KV k="Occurred" v={fmt.format(new Date(selected.occurredAt))} /><KV k="Event category" v={label(selected.category)} /></div> : <p className="muted">No persisted request is selected.</p>}</Panel>
        <Panel title="Adaptive routing path">{route.length ? <div className="route-flow">{route.map((step, index) => <div key={`${step}-${index}`} className="route-node"><span>{index + 1}</span>{label(step)}</div>)}</div> : <p className="muted">This gateway journal entry contains the final request decision but no per-stage route. Detailed inference evidence appears here when it is retained with the event.</p>}</Panel>
      </div>
    </div>
    {selected && <div className="two-columns"><Panel title="Model decision evidence">{hasDetailedEvidence ? <DetectionEvidence detection={detection} /> : <EvidenceFallback event={selected} />}</Panel><Panel title="Inference latency"><Latency latency={latency} total={totalLatency} /></Panel></div>}
    {selected && <FeedbackForm event={selected} submit={(verdict, notes, correctAttackType) => mutate(() => api.submitFeedback(selected.eventId, verdict, notes, correctAttackType), "Feedback submitted to the control-plane review queue.")} />}
  </div>;
}

function Models({ snapshot, api, mutate }: ViewProps) {
  return <div className="stack">
    <SourceStrip items={["Detection service: models actually loaded", "Control service: lifecycle registry"]} />
    <Panel title="Loaded inference models" action={<Badge value={snapshot.detectionReady.status} />}><div className="runtime-models">{Object.entries(snapshot.runtimeModels.models).map(([role, version]) => <article key={role}><span>{label(role)}</span><strong>{version}</strong><small>Serving in detection runtime</small></article>)}</div></Panel>
    <Panel title="Governed model registry" action={<span className="muted">Promotion and assignment are audit logged</span>}><div className="table-wrap"><table><thead><tr><th>Model role</th><th>Artifact version</th><th>Lifecycle</th><th>Evaluation</th><th>Actions</th></tr></thead><tbody>{snapshot.models.map((model) => <tr key={model.modelVersionId}><td><strong>{model.modelName}</strong></td><td>{model.artifactVersion}</td><td><Badge value={model.status} /></td><td><MetricChips json={model.metricsJson} /></td><td className="actions">{model.status !== "ACTIVE" && <button className="small" onClick={() => void mutate(() => api.promote(model.modelVersionId), `${model.modelName} promoted in the lifecycle registry.`)}>Promote</button>}<button className="small secondary" onClick={() => void mutate(() => api.assign(model.modelVersionId), `${model.modelName} assigned to the default application.`)}>Assign</button></td></tr>)}</tbody></table></div></Panel>
  </div>;
}

function TrainingRuns({ runs }: { runs: TrainingRun[] }) {
  return <div className="stack">
    <SourceStrip items={["Security control service", "GET /v1/control/training-runs", "Written by adaptation service"]} />
    <Panel title="Controlled training lifecycle" action={<span className="muted">No candidate is promoted automatically</span>}><div className="table-wrap"><table><thead><tr><th>Run</th><th>Candidate</th><th>Dataset</th><th>Status</th><th>Evaluation</th><th>Outcome</th></tr></thead><tbody>{runs.map((run) => <tr key={run.externalRunId}><td><strong>{shortId(run.externalRunId, 18)}</strong><br /><small>{fmt.format(new Date(run.startedAt))}</small></td><td>{run.modelName}<br /><small>{run.shadowMode ? "Shadow evaluation" : "Managed training"}</small></td><td>{run.datasetVersion}</td><td><Badge value={run.status} /></td><td><MetricChips json={run.metricsJson} /></td><td><DriftSummary run={run} /></td></tr>)}{!runs.length && <tr><td colSpan={6} className="muted">No training lifecycle runs have been registered.</td></tr>}</tbody></table></div></Panel>
  </div>;
}

function PolicyEditor({ snapshot, api, mutate }: ViewProps) {
  const [threshold, setThreshold] = useState(String(snapshot.policy.blockRiskThreshold));
  const [limit, setLimit] = useState(String(snapshot.policy.rateLimitShortWindow));
  useEffect(() => { setThreshold(String(snapshot.policy.blockRiskThreshold)); setLimit(String(snapshot.policy.rateLimitShortWindow)); }, [snapshot.policy]);
  const synchronized = snapshot.policy.version === snapshot.gatewayPolicy.version && snapshot.policy.blockRiskThreshold === snapshot.gatewayPolicy.blockRiskThreshold && snapshot.policy.rateLimitShortWindow === snapshot.gatewayPolicy.rateLimitShortWindow;
  return <div className="stack">
    <SourceStrip items={["Control plane: authoritative policy", "Gateway: currently applied cache"]} />
    <div className="two-columns"><Panel title="Authoritative policy" action={<Badge value={`VERSION ${snapshot.policy.version}`} />}><div className="form-grid"><label>Block-risk threshold<input type="number" min="0" max="1" step="0.01" value={threshold} onChange={(event) => setThreshold(event.target.value)} /></label><label>Short-window request limit<input type="number" min="1" step="1" value={limit} onChange={(event) => setLimit(event.target.value)} /></label></div><button disabled={Number(threshold) < 0 || Number(threshold) > 1 || Number(limit) < 1} onClick={() => void mutate(() => api.updatePolicy({ blockRiskThreshold: Number(threshold), rateLimitShortWindow: Number(limit) }), "A new policy version was saved and queued for gateway refresh.")}>Save new policy version</button><p className="muted">The control service creates an immutable version. The gateway refreshes its cache independently.</p></Panel><Panel title="Gateway enforcement cache" action={<Badge value={synchronized ? "SYNCHRONIZED" : "PENDING"} />}><dl className="kv-list"><KV k="Applied policy version" v={`v${snapshot.gatewayPolicy.version}`} /><KV k="Applied block threshold" v={`${(snapshot.gatewayPolicy.blockRiskThreshold * 100).toFixed(0)}% risk`} /><KV k="Applied short-window limit" v={`${snapshot.gatewayPolicy.rateLimitShortWindow} requests`} /><KV k="Operating mode" v={<Badge value={snapshot.mode.mode} />} /></dl></Panel></div>
  </div>;
}

function IpManagement({ api, mutate }: ViewProps) {
  const [sourceIp, setSourceIp] = useState("");
  const [reason, setReason] = useState("Operator block");
  return <div className="stack"><SourceStrip items={["Security control service", "POST/DELETE /v1/control/blocks", "Gateway lookup: Redis"]} /><Panel title="Manual source-address enforcement"><div className="form-grid"><label>Source IP address<input placeholder="203.0.113.10" value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} /></label><label>Audit reason<input value={reason} onChange={(event) => setReason(event.target.value)} /></label></div><div className="button-row"><button disabled={!sourceIp.trim()} onClick={() => void mutate(() => api.block(sourceIp.trim(), reason), `${sourceIp.trim()} is blocked for one hour.`)}>Block for one hour</button><button className="secondary" disabled={!sourceIp.trim()} onClick={() => void mutate(() => api.unblock(sourceIp.trim()), `${sourceIp.trim()} is no longer manually blocked.`)}>Remove block</button></div><p className="muted">This control writes the source address to the enforcement store and records the administrator action. It does not modify model behavior.</p></Panel></div>;
}

function NetworkIds() {
  const [state, setState] = useState<{ events: NetworkEvidence[]; model_version: string }>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    const load = () => void recentNetworkEvidence().then(setState).catch((reason) => setError(reason instanceof Error ? reason.message : "Network sensor is unavailable"));
    load();
    const timer = window.setInterval(load, 15_000);
    return () => window.clearInterval(timer);
  }, []);
  if (error) return <EmptyState title="Network sensor unavailable" detail={`${error}. HTTP protection continues without network context.`} />;
  if (!state) return <EmptyState title="Loading network evidence" detail="Reading the sensor's current in-memory flow window." />;
  const highest = Math.max(0, ...state.events.map((event) => event.network_risk));
  return <div className="stack"><SourceStrip items={["Network sensor", "GET /v1/network/recent", "Risk context cached in Redis"]} /><div className="metrics-grid"><Metric title="Recent flows" value={String(state.events.length)} detail="Current sensor process window" tone="neutral" /><Metric title="High-risk sources" value={String(state.events.filter((event) => event.network_risk >= .81).length)} detail="At or above the gateway threshold" tone="danger" /><Metric title="Highest network risk" value={`${(highest * 100).toFixed(1)}%`} detail="Across retained flow evidence" tone="warning" /><Metric title="Serving model" value={shortId(state.model_version, 20)} detail="Network detector runtime" tone="success" /></div><Panel title="Recent network classifications"><div className="table-wrap"><table><thead><tr><th>Observed</th><th>Source</th><th>Destination</th><th>Classification</th><th>Risk</th><th>Confidence</th></tr></thead><tbody>{state.events.map((event) => <tr key={`${event.source_ip}-${event.observed_at}`}><td>{fmt.format(new Date(event.observed_at))}</td><td>{event.source_ip}</td><td>{event.destination_ip ?? "Not recorded"}</td><td>{label(event.network_class ?? "UNKNOWN")}</td><td>{(event.network_risk * 100).toFixed(2)}%</td><td>{event.confidence === undefined ? "Not recorded" : `${(event.confidence * 100).toFixed(2)}%`}</td></tr>)}{!state.events.length && <tr><td colSpan={6} className="muted">No flows have been submitted to this sensor instance.</td></tr>}</tbody></table></div></Panel></div>;
}

function Applications({ snapshot }: ViewProps) {
  return <div className="stack"><SourceStrip items={["Security control service", "GET /v1/control/applications", "Gateway upstream registry"]} /><Panel title="Protected application registry"><div className="cards">{snapshot.applications.map((app) => <article className="app-card" key={app.applicationId}><div><strong>{app.name}</strong><p>{app.upstreamUrl}</p><small>{shortId(app.applicationId, 16)}</small></div><Badge value={app.enabled ? "ACTIVE" : "DISABLED"} /></article>)}{!snapshot.applications.length && <p className="muted">No protected applications are registered.</p>}</div></Panel></div>;
}

function Feedback({ snapshot, selected, api, mutate, setSelected }: ViewProps) {
  const reviewEvent = selected ?? snapshot.events[0];
  return <div className="stack">
    <SourceStrip items={["Security control service", "GET/POST /v1/control/feedback", "Consumed by adaptation curation"]} />
    <div className="split-layout"><Panel title="Choose a request"><EventTable events={snapshot.events} selected={reviewEvent} onSelect={setSelected} compact /></Panel>{reviewEvent ? <FeedbackForm event={reviewEvent} submit={(verdict, notes, correctAttackType) => mutate(() => api.submitFeedback(reviewEvent.eventId, verdict, notes, correctAttackType), "Feedback submitted for the next curation run.")} /> : <EmptyState title="No requests available" detail="Feedback can be submitted after the gateway persists a request event." />}</div>
    <Panel title="Submitted feedback"><FeedbackTable feedback={snapshot.feedback} /></Panel>
  </div>;
}

function HealthPanel({ snapshot }: ViewProps) {
  return <div className="stack"><SourceStrip items={["Gateway + control actuators", "Detection + sensor readiness", "Adaptation health"]} /><Panel title="Connected service readiness"><ServiceGrid snapshot={snapshot} /></Panel><Panel title="Control-service dependencies"><HealthComponents health={snapshot.controlHealth} /></Panel></div>;
}

function AuditLog({ snapshot }: ViewProps) {
  return <div className="stack"><SourceStrip items={["Security control service", "GET /v1/control/audit", "Newest changes first"]} /><Panel title="Administrator activity"><div className="table-wrap"><table><thead><tr><th>When</th><th>Actor</th><th>Operation</th><th>Target</th><th>Change summary</th></tr></thead><tbody>{snapshot.audit.map((item) => <tr key={item.auditId}><td>{fmt.format(new Date(item.occurredAt))}</td><td><strong>{item.administrator}</strong></td><td><Badge value={item.action} /></td><td>{label(item.entityType)}<br /><small>{shortId(item.entityId, 18)}</small></td><td><AuditSummary item={item} /></td></tr>)}{!snapshot.audit.length && <tr><td colSpan={5} className="muted">No administrative changes are recorded.</td></tr>}</tbody></table></div></Panel></div>;
}

function Settings({ username, signOut }: ViewProps) {
  return <div className="two-columns"><Panel title="Operator session"><div className="session-profile"><span>{username.slice(0, 1).toUpperCase()}</span><div><strong>{username}</strong><p>Administrator · authenticated locally</p></div></div><button className="secondary" onClick={signOut}>Sign out</button><p className="muted">Credentials remain in memory for this tab and are not written to browser storage.</p></Panel><Panel title="Dashboard service map"><dl className="kv-list"><KV k="Traffic and enforcement" v="Gateway · :8080" /><KV k="Inference runtime" v="Detection · :8000" /><KV k="Governance and audit" v="Control · :8082" /><KV k="Network context" v="Sensor · :8083" /><KV k="Training lifecycle" v="Adaptation · :8084" /><KV k="Automatic refresh" v="Every 15 seconds" /></dl></Panel></div>;
}

function DetectionEvidence({ detection }: { detection: JsonRecord }) {
  const triage = asRecord(detection.triage);
  const router = asRecord(detection.router);
  const experts = pick<unknown[]>(detection, "expertOutputs", "expert_outputs") ?? [];
  const deep = asRecord(pick(detection, "deepOutput", "deep_output"));
  const versions = asRecord(pick(detection, "modelVersions", "model_versions"));
  const risks = asRecord(detection.risks);
  return <div className="evidence-stack">
    {triage && <div className="evidence-row"><strong>Triage</strong><span>{label(scalar(triage.decision))}</span><small>{percent(pick<number>(triage, "suspiciousProbability", "suspicious_probability"))} suspicious</small></div>}
    {router && <div className="evidence-row"><strong>Router</strong><span>{(pick<unknown[]>(router, "selectedExperts", "selected_experts") ?? []).map(String).map(label).join(", ") || "No expert selected"}</span><small><ScoreSummary scores={asRecord(router.scores)} /></small></div>}
    {experts.map((entry, index) => <OutputSummary key={index} title={`Fast expert ${index + 1}`} output={asRecord(entry)} />)}
    {deep && <OutputSummary title="Deep escalation" output={deep} />}
    {risks && <div className="evidence-row"><strong>Fused risk</strong><span>{percent(risks.overall)}</span><small>HTTP {percent(risks.http)} · Behaviour {percent(risks.behaviour)} · Network {percent(risks.network)}</small></div>}
    {versions && <div className="model-version-list">{Object.entries(versions).map(([role, version]) => <span key={role}>{label(role)} <strong>{String(version)}</strong></span>)}</div>}
  </div>;
}

function EvidenceFallback({ event }: { event: EventRecord }) {
  return <div className="evidence-stack"><div className="evidence-row"><strong>Final gateway decision</strong><span>{label(event.predictedAttack ?? "UNKNOWN")}</span><small>{(event.risk * 100).toFixed(2)}% risk · {label(event.action ?? "UNKNOWN")}</small></div><p className="muted">The event journal retained the sanitized final decision only. No triage, router, expert, or deep-model payload was persisted for this request.</p></div>;
}

function OutputSummary({ title, output }: { title: string; output?: JsonRecord }) {
  if (!output) return null;
  return <div className="evidence-row"><strong>{title}</strong><span>{label(scalar(pick(output, "predictedAttack", "predicted_attack")))}</span><small>{percent(output.confidence)} confidence · {percent(output.risk)} risk · {scalar(pick(output, "modelVersion", "model_version"))}</small></div>;
}

function ServiceGrid({ snapshot, compact = false }: { snapshot: DashboardSnapshot; compact?: boolean }) {
  const rows = serviceRows(snapshot);
  return <div className={`service-grid ${compact ? "compact" : ""}`}>{rows.map((service) => <article key={service.name}><div><span className={`dot ${statusTone(service.status)}`} /><strong>{service.name}</strong></div><Badge value={service.status} /><p>{service.detail}</p><small>{service.endpoint}</small></article>)}</div>;
}

function serviceRows(snapshot: DashboardSnapshot) {
  return [
    { name: "Gateway", status: healthStatus(snapshot.gatewayHealth), detail: `${label(snapshot.mode.mode)} mode · policy v${snapshot.gatewayPolicy.version}`, endpoint: "GET /gateway-api/actuator/health" },
    { name: "Detection", status: healthStatus(snapshot.detectionReady), detail: `${Object.keys(snapshot.runtimeModels.models).length} inference models loaded`, endpoint: "GET /detection-api/ready" },
    { name: "Control plane", status: healthStatus(snapshot.controlHealth), detail: "Policy, registry, events, feedback, and audit", endpoint: "GET /control-api/actuator/health" },
    { name: "Network sensor", status: healthStatus(snapshot.sensorHealth), detail: `Redis ${snapshot.sensorHealth.redis ?? "unknown"} · ${snapshot.sensorHealth.model_version ?? "model unavailable"}`, endpoint: "GET /sensor-api/health" },
    { name: "Adaptation", status: healthStatus(snapshot.adaptationHealth), detail: "Curation, drift, and candidate lifecycle", endpoint: "GET /adaptation-api/health" }
  ];
}

function HealthComponents({ health }: { health: Health }) {
  const components = Object.entries(health.components ?? {});
  if (!components.length) return <p className="muted">The control actuator reports aggregate readiness. Dependency-level detail is intentionally not exposed by its current health policy.</p>;
  return <dl className="kv-list">{components.map(([name, component]) => <KV key={name} k={label(name)} v={<Badge value={component.status} />} />)}</dl>;
}

function MetricChips({ json }: { json?: string }) {
  const metrics = parseJson(json);
  const entries = Object.entries(metrics).filter(([, value]) => typeof value === "number" || typeof value === "string");
  if (!entries.length) return <span className="muted">No metrics recorded</span>;
  return <div className="metric-chips">{entries.slice(0, 4).map(([name, value]) => <span key={name}><small>{label(name)}</small><strong>{formatMetric(name, value)}</strong></span>)}</div>;
}

function formatMetric(name: string, value: unknown) {
  const number = Number(value);
  if (!Number.isFinite(number)) return scalar(value);
  const key = name.toLowerCase();
  if (key.includes("ms") || key.includes("latency")) return `${number.toFixed(2)} ms`;
  if (["f1", "recall", "accuracy", "coverage", "ece", "precision", "risk", "confidence"].some((token) => key.includes(token))) return `${(number * 100).toFixed(number >= .9995 ? 2 : 1)}%`;
  return number.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
}

function DriftSummary({ run }: { run: TrainingRun }) {
  const drift = parseJson(run.driftJson);
  if (typeof drift.reason === "string") return <span className="failure-note">{drift.reason}</span>;
  const entries = Object.entries(drift);
  if (!entries.length) return <span className="muted">No drift flagged</span>;
  return <span>{entries.slice(0, 2).map(([name, value]) => `${label(name)}: ${scalar(value)}`).join(" · ")}</span>;
}

function AuditSummary({ item }: { item: Audit }) {
  const next = parseJson(item.newValueJson);
  const previous = parseJson(item.oldValueJson);
  const preferred = ["modelName", "artifactVersion", "status", "version", "blockRiskThreshold", "rateLimitShortWindow", "sourceIp", "reason", "shadowMode", "applicationId"];
  const entries = preferred.filter((key) => next[key] !== undefined).map((key) => [key, next[key]] as const);
  if (!entries.length) {
    const changed = Object.keys(next).filter((key) => scalar(next[key]) !== scalar(previous[key]) && !["metricsJson", "driftJson", "comparison", "metrics"].includes(key));
    entries.push(...changed.slice(0, 3).map((key) => [key, next[key]] as const));
  }
  if (!entries.length) return <span className="muted">Lifecycle metadata recorded</span>;
  return <div className="change-summary">{entries.slice(0, 3).map(([key, value]) => <span key={key}><small>{label(key)}</small><strong>{scalar(value)}</strong></span>)}</div>;
}

function FeedbackTable({ feedback }: { feedback: FeedbackRecord[] }) {
  return <div className="table-wrap"><table><thead><tr><th>Submitted</th><th>Request</th><th>Original decision</th><th>Administrator verdict</th><th>Reviewer</th></tr></thead><tbody>{feedback.map((item) => <tr key={item.feedbackId}><td>{fmt.format(new Date(item.submittedAt))}</td><td><strong>{item.method ?? "?"} {item.path ?? "Unknown path"}</strong><br /><small>{shortId(item.eventId, 18)}</small></td><td>{label(item.predictedAttack ?? "UNKNOWN")}</td><td><Badge value={item.verdict} />{item.correctAttackType && <small className="block-note">Corrected to {label(item.correctAttackType)}</small>}{item.notes && <small className="block-note">{item.notes}</small>}</td><td>{item.submittedBy}</td></tr>)}{!feedback.length && <tr><td colSpan={5} className="muted">No administrator feedback has been submitted.</td></tr>}</tbody></table></div>;
}

function FeedbackForm({ event, submit }: { event: EventRecord; submit: (verdict: string, notes: string, correctAttackType?: string) => Promise<void> }) {
  const [verdict, setVerdict] = useState("CONFIRMED_ATTACK");
  const [notes, setNotes] = useState("");
  const [correctAttackType, setCorrectAttackType] = useState("SQL_INJECTION");
  return <Panel title="Review selected decision" action={<Badge value={event.predictedAttack} />}><p className="muted">{event.method ?? "?"} {event.path ?? "/"} · {shortId(event.eventId, 20)}</p><div className="form-grid"><label>Administrator verdict<select value={verdict} onChange={(change) => setVerdict(change.target.value)}><option value="CONFIRMED_ATTACK">Confirmed attack</option><option value="FALSE_POSITIVE">False positive</option><option value="WRONG_ATTACK_TYPE">Wrong attack type</option><option value="BENIGN">Benign</option></select></label>{verdict === "WRONG_ATTACK_TYPE" ? <label>Correct attack type<select value={correctAttackType} onChange={(change) => setCorrectAttackType(change.target.value)}><option value="SQL_INJECTION">SQL injection</option><option value="XSS">Cross-site scripting</option><option value="COOKIE_INJECTION">Cookie injection</option><option value="DIRECTORY_TRAVERSAL">Directory traversal</option><option value="REMOTE_CODE_EXECUTION">Remote code execution</option></select></label> : <label>Review note<input value={notes} onChange={(change) => setNotes(change.target.value)} placeholder="Why is this verdict correct?" /></label>}</div><button onClick={() => void submit(verdict, notes, verdict === "WRONG_ATTACK_TYPE" ? correctAttackType : undefined)}>Submit review</button><p className="muted">Feedback is stored for curated retraining. It never promotes a model or changes policy automatically.</p></Panel>;
}

function SourceStrip({ items }: { items: string[] }) { return <div className="source-strip" aria-label="Data sources">{items.map((item) => <span key={item}>{item}</span>)}</div>; }
function Metric({ title, value, detail, tone }: { title: string; value: string; detail: string; tone: string }) { return <article className={`metric ${tone}`}><p>{title}</p><strong>{value}</strong><small>{detail}</small></article>; }
function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) { return <section className="panel"><header><h2>{title}</h2>{action}</header>{children}</section>; }
function KV({ k, v }: { k: string; v: ReactNode }) { return <div><dt>{k}</dt><dd>{v}</dd></div>; }
function Badge({ value }: { value?: string }) { return <span className={`badge ${statusTone(value)}`}>{label(value ?? "UNKNOWN")}</span>; }
function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="empty-state"><h2>{title}</h2><p>{detail}</p></div>; }

function EventTable({ events, selected, onSelect, compact = false }: { events: EventRecord[]; selected?: EventRecord; onSelect?: (event: EventRecord) => void; compact?: boolean }) {
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Request</th>{!compact && <th>Classification</th>}<th>Risk</th><th>Action</th></tr></thead><tbody>{events.map((event) => <tr className={selected?.eventId === event.eventId ? "selected" : ""} key={event.eventId} onClick={() => onSelect?.(event)}><td>{fmt.format(new Date(event.occurredAt))}</td><td><strong>{event.method ?? "?"}</strong> <span className="path">{event.path ?? "/"}</span>{!compact && <small className="block-note">HTTP {event.statusCode}</small>}</td>{!compact && <td>{label(event.predictedAttack ?? "UNKNOWN")}</td>}<td>{(event.risk * 100).toFixed(1)}%</td><td><Badge value={event.action} /></td></tr>)}{!events.length && <tr><td colSpan={compact ? 4 : 5} className="muted">No matching persisted requests.</td></tr>}</tbody></table></div>;
}

function AttackBreakdown({ events }: { events: EventRecord[] }) {
  const counts = events.reduce<Record<string, number>>((result, event) => { const key = event.predictedAttack ?? "UNKNOWN"; result[key] = (result[key] ?? 0) + 1; return result; }, {});
  return <div className="cards">{Object.entries(counts).map(([attack, count]) => <article className="mini-card" key={attack}><Badge value={attack === "BENIGN" ? "ALLOW" : "BLOCK"} /><strong>{count}</strong><span>{label(attack)}</span></article>)}{!Object.keys(counts).length && <article className="mini-card"><Badge value="CLEAR" /><strong>0</strong><span>No detections in the retained window</span></article>}</div>;
}

function ScoreSummary({ scores }: { scores?: JsonRecord }) {
  if (!scores) return <>No confidence scores retained</>;
  return <>{Object.entries(scores).map(([name, value]) => `${label(name)} ${percent(value)}`).join(" · ")}</>;
}

function Latency({ latency, total }: { latency?: Record<string, number>; total?: number }) {
  if (!latency || !Object.keys(latency).length) return <p className="muted">Per-stage latency was not persisted for this gateway event.</p>;
  const maximum = Math.max(1, ...Object.values(latency).map(Number));
  return <div className="bars">{Object.entries(latency).map(([name, value]) => <div key={name}><div><span>{label(name)}</span><strong>{Number(value).toFixed(2)} ms</strong></div><i><b style={{ width: `${Math.min(100, (Number(value) / maximum) * 100)}%` }} /></i></div>)}{total !== undefined && <p className="latency-total">Total inference latency <strong>{total.toFixed(2)} ms</strong></p>}</div>;
}

function isDetection(event: EventRecord) { return event.action === "BLOCK" || (event.predictedAttack !== undefined && !["BENIGN", "UNAVAILABLE"].includes(event.predictedAttack)); }
function shortId(value?: string, size = 12) { if (!value) return "Not recorded"; return value.length > size ? `${value.slice(0, size)}...` : value; }
function percent(value: unknown) { const number = Number(value); return Number.isFinite(number) ? `${(number * 100).toFixed(2)}%` : "Not recorded"; }
