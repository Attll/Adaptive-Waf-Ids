import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, DashboardApi, recentNetworkEvidence, type Application, type Audit, type EventRecord, type GatewayMode, type GatewayPolicy, type Health, type Model, type NetworkEvidence, type Policy } from "./api";

type Section = "Overview" | "Live Traffic" | "Security Events" | "Attack Explorer" | "Request Inspector" | "Routing Explorer" | "Models" | "Model Versions" | "Training Runs" | "Rules" | "Policies" | "Rate Limits" | "IP Management" | "Network IDS" | "Protected Applications" | "Feedback Queue" | "System Health" | "Audit Log" | "Settings";
type Snapshot = { policy: Policy; events: EventRecord[]; models: Model[]; applications: Application[]; audit: Audit[]; controlHealth: Health; mode: GatewayMode; gatewayPolicy: GatewayPolicy };

const sections: Section[] = ["Overview", "Live Traffic", "Security Events", "Attack Explorer", "Request Inspector", "Routing Explorer", "Models", "Model Versions", "Training Runs", "Rules", "Policies", "Rate Limits", "IP Management", "Network IDS", "Protected Applications", "Feedback Queue", "System Health", "Audit Log", "Settings"];
const navGroups: [string, Section[]][] = [["Observe", sections.slice(0, 6)], ["Control", sections.slice(6, 15)], ["Operate", sections.slice(15)]];

const fmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", month: "short", day: "numeric" });
const statusTone = (value?: string) => value === "BLOCK" || value === "DOWN" || value === "DEGRADED" ? "danger" : value === "ACTIVE" || value === "UP" || value === "NORMAL" || value === "ALLOW" ? "success" : "warning";
const parseDetails = (event?: EventRecord) => { try { return event ? JSON.parse(event.detailsJson) as Record<string, unknown> : {}; } catch { return {}; } };
const label = (name: string) => name.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());

export function App() {
  const [section, setSection] = useState<Section>("Overview");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [selected, setSelected] = useState<EventRecord>();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("Connect with an administrator account to view live security data.");
  const [lastRefresh, setLastRefresh] = useState<Date>();

  const api = useMemo(() => username && password ? new DashboardApi(username, password) : undefined, [username, password]);
  const refresh = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    try {
      const next = await api.snapshot();
      setSnapshot(next);
      setSelected((current) => next.events.find((event) => event.eventId === current?.eventId) ?? next.events[0]);
      setMessage("Live control-plane data loaded.");
      setLastRefresh(new Date());
    } catch (error) {
      setMessage(error instanceof ApiError && error.status === 401 ? "Authentication failed. Check the administrator credentials." : `Unable to load live data: ${error instanceof Error ? error.message : "unknown error"}`);
    } finally { setLoading(false); }
  }, [api]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!api) return;
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [api, refresh]);

  const mutate = async (action: () => Promise<unknown>, success: string) => {
    try { await action(); setMessage(success); await refresh(); }
    catch (error) { setMessage(`Action failed: ${error instanceof Error ? error.message : "unknown error"}`); }
  };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">A</span><div><strong>Adaptive WAF</strong><small>Security console</small></div></div>
      <nav>{navGroups.map(([group, entries]) => <div className="nav-group" key={group}><p>{group}</p>{entries.map((entry) => <button key={entry} className={section === entry ? "nav-item active" : "nav-item"} onClick={() => setSection(entry)}><span>{iconFor(entry)}</span>{entry}</button>)}</div>)}</nav>
      <div className="sidebar-footer"><span className={`dot ${statusTone(snapshot?.mode.mode)}`} />{snapshot ? `${label(snapshot.mode.mode)} mode` : "Control plane offline"}</div>
    </aside>
    <main>
      <header className="topbar"><div><p className="eyebrow">Adaptive Intelligent WAF</p><h1>{section}</h1></div><div className="top-actions"><span className="refresh-note">{lastRefresh ? `Updated ${fmt.format(lastRefresh)}` : "Not connected"}</span><button className="secondary" onClick={() => void refresh()} disabled={!api || loading}>{loading ? "Refreshing…" : "Refresh"}</button><button className="user-chip" onClick={() => setSection("Settings")}>{username || "Sign in"}</button></div></header>
      <div className="notice" role="status"><span className={`dot ${snapshot ? "success" : "warning"}`} />{message}</div>
      <section className="content">{renderSection(section, { snapshot, selected, setSelected, api, mutate, username, setUsername, password, setPassword, setSection })}</section>
    </main>
  </div>;
}

type ViewProps = { snapshot?: Snapshot; selected?: EventRecord; setSelected: (event: EventRecord) => void; api?: DashboardApi; mutate: (action: () => Promise<unknown>, success: string) => Promise<void>; username: string; setUsername: (value: string) => void; password: string; setPassword: (value: string) => void; setSection: (section: Section) => void };

function renderSection(section: Section, props: ViewProps) {
  if (!props.snapshot && section !== "Settings") return <ConnectCard onSettings={() => props.setSection("Settings")} />;
  switch (section) {
    case "Overview": return <Overview {...props} />;
    case "Security Events": case "Live Traffic": case "Attack Explorer": return <Events {...props} mode={section} />;
    case "Request Inspector": return <Inspector {...props} />;
    case "Routing Explorer": return <Routing {...props} />;
    case "Models": case "Model Versions": return <Models {...props} />;
    case "Policies": case "Rate Limits": case "Rules": return <PolicyEditor {...props} />;
    case "IP Management": return <IpManagement {...props} />;
    case "Network IDS": return <NetworkIds />;
    case "Protected Applications": return <Applications {...props} />;
    case "System Health": return <HealthPanel {...props} />;
    case "Audit Log": return <AuditLog {...props} />;
    case "Feedback Queue": return <Feedback {...props} />;
    case "Settings": return <Settings {...props} />;
    default: return <Planned section={section} />;
  }
}

function ConnectCard({ onSettings }: { onSettings: () => void }) { return <div className="empty-state"><div className="empty-icon">⌁</div><h2>Connect to the control plane</h2><p>Live views deliberately do not display mock data. Add an administrator account in Settings to load events, policies, models, and health.</p><button onClick={onSettings}>Open settings</button></div>; }

function Overview({ snapshot, setSection }: ViewProps) {
  const data = snapshot!; const events = data.events;
  const blocked = events.filter((event) => event.action === "BLOCK").length;
  const attacks = events.filter((event) => event.predictedAttack && event.predictedAttack !== "BENIGN").length;
  const risk = events.length ? events.reduce((total, event) => total + event.risk, 0) / events.length : 0;
  return <div className="stack"><div className="metrics-grid">
    <Metric title="Events observed" value={String(events.length)} detail="Latest 100 persisted events" tone="neutral" />
    <Metric title="Blocked" value={String(blocked)} detail={events.length ? `${Math.round((blocked / events.length) * 100)}% of live window` : "Awaiting traffic"} tone="danger" />
    <Metric title="Detected attacks" value={String(attacks)} detail="Non-benign classifications" tone="warning" />
    <Metric title="Mean HTTP risk" value={`${(risk * 100).toFixed(1)}%`} detail={`Policy blocks at ${(data.policy.blockRiskThreshold * 100).toFixed(0)}%`} tone="success" />
  </div><div className="two-columns"><Panel title="Security events" action={<button className="text-button" onClick={() => setSection("Security Events")}>View all</button>}><EventTable events={events.slice(0, 6)} /></Panel><Panel title="Protection posture"><dl className="kv-list"><KV k="Operating mode" v={<Badge value={data.mode.mode} />} /><KV k="Policy version" v={`v${data.policy.version}`} /><KV k="Short-window limit" v={`${data.gatewayPolicy.rateLimitShortWindow} requests`} /><KV k="Active models" v={String(data.models.filter((model) => model.status === "ACTIVE").length)} /><KV k="Protected applications" v={String(data.applications.filter((app) => app.enabled).length)} /></dl></Panel></div><div className="two-columns"><Panel title="Routing distribution"><RouteBars events={events} /></Panel><Panel title="System health"><HealthSummary health={data.controlHealth} mode={data.mode.mode} /></Panel></div></div>;
}

function Events({ snapshot, selected, setSelected, mode }: ViewProps & { mode: string }) {
  const [filter, setFilter] = useState("");
  const events = snapshot!.events.filter((event) => `${event.path} ${event.predictedAttack} ${event.action} ${event.sourceHash}`.toLowerCase().includes(filter.toLowerCase()));
  return <div className="stack"><div className="toolbar"><input aria-label="Filter events" placeholder="Filter by path, attack, action, source hash" value={filter} onChange={(event) => setFilter(event.target.value)} /><span>{events.length} live records</span></div>{mode === "Attack Explorer" && <AttackBreakdown events={events} />}<Panel title={mode === "Live Traffic" ? "Live traffic records" : "Persisted security events"}><EventTable events={events} selected={selected} onSelect={setSelected} /></Panel></div>;
}

function Inspector({ selected, snapshot, mutate, api, setSelected }: ViewProps) {
  const details = parseDetails(selected); const detection = (details.detection ?? details) as Record<string, unknown>;
  const route = Array.isArray(detection.routingPath) ? detection.routingPath as string[] : [];
  const models = detection.modelVersions as Record<string, string> | undefined;
  const latency = detection.latencyByStageMs as Record<string, number> | undefined;
  return <div className="stack"><div className="split-layout"><Panel title="Recent requests"><EventTable events={snapshot!.events} selected={selected} onSelect={setSelected} compact /></Panel><div className="stack"><Panel title="Request decision" action={selected ? <Badge value={selected.action ?? "UNKNOWN"} /> : undefined}>{selected ? <div className="decision-grid"><KV k="Request ID" v={selected.requestId ?? "Not recorded"} /><KV k="Event ID" v={selected.eventId} /><KV k="Source (hashed)" v={selected.sourceHash ?? "Not recorded"} /><KV k="Request" v={`${selected.method ?? "?"} ${selected.path ?? "/"}`} /><KV k="Classification" v={label(selected.predictedAttack ?? "UNKNOWN")} /><KV k="HTTP risk" v={`${(selected.risk * 100).toFixed(3)}%`} /><KV k="Status" v={String(selected.statusCode)} /><KV k="Occurred" v={fmt.format(new Date(selected.occurredAt))} /></div> : <p>No persisted request selected.</p>}</Panel><Panel title="Adaptive routing path">{route.length ? <div className="route-flow">{route.map((step, index) => <div key={step} className="route-node"><span>{index + 1}</span>{label(step)}</div>)}</div> : <p className="muted">This event did not retain detailed inference telemetry.</p>}</Panel></div></div>{selected && <div className="two-columns"><Panel title="Model evidence"><JsonDetails value={{ triage: detection.triage, router: detection.router, expertOutputs: detection.expertOutputs, deepOutput: detection.deepOutput, modelVersions: models }} /></Panel><Panel title="Latency by stage"><Latency latency={latency} total={typeof detection.totalLatencyMs === "number" ? detection.totalLatencyMs : undefined} /></Panel></div>}{selected && api && <FeedbackForm event={selected} submit={(verdict, notes) => mutate(() => api.submitFeedback(selected.eventId, verdict, notes), "Feedback submitted and audit logged.")} />}</div>;
}

function Routing({ snapshot }: ViewProps) { const events = snapshot!.events; return <div className="stack"><Panel title="Pipeline exits"><RouteBars events={events} /><p className="muted">Routing is derived from persisted event evidence. Events without full telemetry are excluded from detailed-stage counts.</p></Panel><Panel title="Pipeline model"><div className="pipeline"><span>Request</span><i>↓</i><span>Triage</span><i>↓</i><span>Router</span><i>↓</i><span>Fast expert</span><i>↓</i><span>Deep escalation</span><i>↓</i><span>Policy decision</span></div></Panel></div>; }

function Models({ snapshot, api, mutate }: ViewProps) { return <Panel title="Registered model versions" action={<span className="muted">Promotions are manual and audit logged</span>}><div className="table-wrap"><table><thead><tr><th>Model</th><th>Artifact</th><th>Status</th><th>Metrics</th><th>Actions</th></tr></thead><tbody>{snapshot!.models.map((model) => <tr key={model.modelVersionId}><td><strong>{model.modelName}</strong></td><td>{model.artifactVersion}</td><td><Badge value={model.status} /></td><td><code>{model.metricsJson}</code></td><td className="actions">{api && model.status !== "ACTIVE" && <button className="small" onClick={() => void mutate(() => api.promote(model.modelVersionId), `${model.modelName} promoted; gateway assignment remains explicit.`)}>Promote</button>}{api && <button className="small secondary" onClick={() => void mutate(() => api.assign(model.modelVersionId), `${model.modelName} assigned to the default protected application.`)}>Assign</button>}</td></tr>)}</tbody></table></div></Panel>; }

function PolicyEditor({ snapshot, api, mutate }: ViewProps) { const [threshold, setThreshold] = useState(String(snapshot!.policy.blockRiskThreshold)); const [limit, setLimit] = useState(String(snapshot!.policy.rateLimitShortWindow)); useEffect(() => { setThreshold(String(snapshot!.policy.blockRiskThreshold)); setLimit(String(snapshot!.policy.rateLimitShortWindow)); }, [snapshot]); return <div className="two-columns"><Panel title="Active policy"><div className="form-grid"><label>Block-risk threshold<input type="number" min="0" max="1" step="0.01" value={threshold} onChange={(event) => setThreshold(event.target.value)} /></label><label>Short-window rate limit<input type="number" min="1" step="1" value={limit} onChange={(event) => setLimit(event.target.value)} /></label></div>{api && <button onClick={() => void mutate(() => api.updatePolicy({ blockRiskThreshold: Number(threshold), rateLimitShortWindow: Number(limit) }), "Policy saved as a new version and queued for gateway refresh.")}>Save policy</button>}<p className="muted">Changes create a new immutable policy version and are picked up from the gateway cache.</p></Panel><Panel title="Gateway cache"><dl className="kv-list"><KV k="Applied policy version" v={`v${snapshot!.gatewayPolicy.version}`} /><KV k="Applied threshold" v={snapshot!.gatewayPolicy.blockRiskThreshold.toFixed(2)} /><KV k="Applied rate limit" v={`${snapshot!.gatewayPolicy.rateLimitShortWindow} requests`} /><KV k="Current operating mode" v={<Badge value={snapshot!.mode.mode} />} /></dl></Panel></div>; }

function IpManagement({ api, mutate }: ViewProps) { const [sourceIp, setSourceIp] = useState(""); const [reason, setReason] = useState("Operator block"); return <Panel title="Manual IP block"><div className="form-grid"><label>Source IP<input placeholder="203.0.113.10" value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} /></label><label>Reason<input value={reason} onChange={(event) => setReason(event.target.value)} /></label></div><div className="button-row">{api && <button disabled={!sourceIp} onClick={() => void mutate(() => api.block(sourceIp, reason), `${sourceIp} is blocked in Redis and recorded in the control plane.`)}>Block IP</button>}{api && <button className="secondary" disabled={!sourceIp} onClick={() => void mutate(() => api.unblock(sourceIp), `${sourceIp} is no longer manually blocked.`)}>Unblock IP</button>}</div><p className="muted">Manual blocks are scoped to the supplied source address, expire by policy, and generate audit entries.</p></Panel>; }

function Applications({ snapshot }: ViewProps) { return <Panel title="Protected applications"><div className="cards">{snapshot!.applications.map((app) => <article className="app-card" key={app.applicationId}><div><strong>{app.name}</strong><p>{app.upstreamUrl}</p></div><Badge value={app.enabled ? "ACTIVE" : "DISABLED"} /></article>)}</div></Panel>; }
function NetworkIds() {
  const [state, setState] = useState<{ events: NetworkEvidence[]; model_version: string }>();
  const [error, setError] = useState<string>();
  useEffect(() => { void recentNetworkEvidence().then(setState).catch((reason) => setError(reason instanceof Error ? reason.message : "Network sensor is unavailable")); }, []);
  if (error) return <div className="empty-state"><div className="empty-icon">⌁</div><h2>Network sensor unavailable</h2><p>{error}. HTTP protection continues fail-open for missing network context.</p></div>;
  if (!state) return <div className="empty-state"><div className="empty-icon">⌁</div><h2>Loading network evidence</h2><p>Reading current source-risk evidence from the asynchronous sensor.</p></div>;
  return <div className="stack"><div className="metrics-grid"><Metric title="Recent flow evidence" value={String(state.events.length)} detail={`Model ${state.model_version}`} tone="neutral" /><Metric title="High-risk sources" value={String(state.events.filter((event) => event.network_risk >= .81).length)} detail="Current in-memory sensor window" tone="danger" /><Metric title="Highest risk" value={`${((Math.max(0, ...state.events.map((event) => event.network_risk))) * 100).toFixed(1)}%`} detail="TTL-backed Redis context" tone="warning" /><Metric title="Sensor mode" value="Live" detail="Asynchronous to HTTP traffic" tone="success" /></div><Panel title="Live network evidence"><div className="table-wrap"><table><thead><tr><th>Observed</th><th>Source</th><th>Classification</th><th>Risk</th><th>Confidence</th><th>Model</th></tr></thead><tbody>{state.events.map((event) => <tr key={`${event.source_ip}-${event.observed_at}`}><td>{fmt.format(new Date(event.observed_at))}</td><td>{event.source_ip}</td><td>{label(event.network_class ?? "UNKNOWN")}</td><td>{(event.network_risk * 100).toFixed(3)}%</td><td>{event.confidence === undefined ? "—" : `${(event.confidence * 100).toFixed(2)}%`}</td><td>{event.model_version}</td></tr>)}{!state.events.length && <tr><td colSpan={6} className="muted">No flows have been observed by this sensor instance.</td></tr>}</tbody></table></div></Panel></div>;
}
function HealthPanel({ snapshot }: ViewProps) { return <div className="two-columns"><Panel title="Security control service"><HealthSummary health={snapshot!.controlHealth} mode="UP" /></Panel><Panel title="Gateway"><dl className="kv-list"><KV k="Operating mode" v={<Badge value={snapshot!.mode.mode} />} /><KV k="Policy cache" v={`v${snapshot!.gatewayPolicy.version}`} /><KV k="Risk threshold" v={snapshot!.gatewayPolicy.blockRiskThreshold.toFixed(2)} /></dl></Panel></div>; }
function AuditLog({ snapshot }: ViewProps) { return <Panel title="Administrator audit trail"><div className="table-wrap"><table><thead><tr><th>When</th><th>Administrator</th><th>Action</th><th>Entity</th><th>Values</th></tr></thead><tbody>{snapshot!.audit.map((item) => <tr key={item.auditId}><td>{fmt.format(new Date(item.occurredAt))}</td><td>{item.administrator}</td><td><Badge value={item.action} /></td><td>{item.entityType}<br /><small>{item.entityId}</small></td><td><code>{item.newValueJson ?? "—"}</code></td></tr>)}</tbody></table></div></Panel>; }
function Feedback({ snapshot, api, mutate }: ViewProps) { const attack = snapshot!.events.find((event) => event.predictedAttack !== "BENIGN"); return attack && api ? <FeedbackForm event={attack} submit={(verdict, notes) => mutate(() => api.submitFeedback(attack.eventId, verdict, notes), "Feedback submitted for curation; no model was automatically promoted.")} /> : <Planned section="Feedback Queue" />; }
function Settings({ username, setUsername, password, setPassword }: ViewProps) { return <div className="two-columns"><Panel title="Administrator connection"><div className="form-grid"><label>Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="admin" /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Administrator password" /></label></div><p className="muted">Credentials are retained only in this browser tab’s application memory and are sent over the local Vite proxy to the control-plane API.</p></Panel><Panel title="Development endpoints"><dl className="kv-list"><KV k="Control service" v="http://127.0.0.1:8082" /><KV k="Gateway" v="http://127.0.0.1:8080" /><KV k="Dashboard" v="http://127.0.0.1:5173" /><KV k="Refresh interval" v="15 seconds" /></dl></Panel></div>; }
function Planned({ section }: { section: string }) { return <div className="empty-state"><div className="empty-icon">◌</div><h2>{section}</h2><p>This console route is reserved for the corresponding live service introduced in a later phase. It intentionally does not invent operational data.</p></div>; }

function Metric({ title, value, detail, tone }: { title: string; value: string; detail: string; tone: string }) { return <article className={`metric ${tone}`}><p>{title}</p><strong>{value}</strong><small>{detail}</small></article>; }
function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) { return <section className="panel"><header><h2>{title}</h2>{action}</header>{children}</section>; }
function KV({ k, v }: { k: string; v: ReactNode }) { return <div><dt>{k}</dt><dd>{v}</dd></div>; }
function Badge({ value }: { value?: string }) { return <span className={`badge ${statusTone(value)}`}>{label(value ?? "UNKNOWN")}</span>; }
function EventTable({ events, selected, onSelect, compact = false }: { events: EventRecord[]; selected?: EventRecord; onSelect?: (event: EventRecord) => void; compact?: boolean }) { return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Request</th>{!compact && <th>Attack</th>}<th>Risk</th><th>Action</th></tr></thead><tbody>{events.map((event) => <tr className={selected?.eventId === event.eventId ? "selected" : ""} key={event.eventId} onClick={() => onSelect?.(event)}><td>{fmt.format(new Date(event.occurredAt))}</td><td><strong>{event.method}</strong> <span className="path">{event.path}</span></td>{!compact && <td>{label(event.predictedAttack ?? "UNKNOWN")}</td>}<td>{(event.risk * 100).toFixed(1)}%</td><td><Badge value={event.action} /></td></tr>)}{!events.length && <tr><td colSpan={compact ? 4 : 5} className="muted">No matching persisted events.</td></tr>}</tbody></table></div>; }
function AttackBreakdown({ events }: { events: EventRecord[] }) { const counts = events.reduce<Record<string, number>>((result, event) => { const key = event.predictedAttack ?? "UNKNOWN"; result[key] = (result[key] ?? 0) + 1; return result; }, {}); return <div className="cards">{Object.entries(counts).map(([attack, count]) => <article className="mini-card" key={attack}><Badge value={attack === "BENIGN" ? "ALLOW" : "BLOCK"} /><strong>{count}</strong><span>{label(attack)}</span></article>)}</div>; }
function RouteBars({ events }: { events: EventRecord[] }) { const counts = events.reduce<Record<string, number>>((result, event) => { const route = parseDetails(event).routingPath; if (Array.isArray(route)) route.forEach((entry) => { result[String(entry)] = (result[String(entry)] ?? 0) + 1; }); return result; }, {}); const max = Math.max(1, ...Object.values(counts)); return <div className="bars">{Object.keys(counts).length ? Object.entries(counts).map(([step, count]) => <div key={step}><div><span>{label(step)}</span><strong>{count}</strong></div><i><b style={{ width: `${(count / max) * 100}%` }} /></i></div>) : <p className="muted">No detailed routing telemetry is available yet.</p>}</div>; }
function HealthSummary({ health, mode }: { health: Health; mode: string }) { return <dl className="kv-list"><KV k="Service status" v={<Badge value={health.status} />} /><KV k="Operating status" v={<Badge value={mode} />} />{Object.entries(health.components ?? {}).map(([name, component]) => <KV key={name} k={label(name)} v={<Badge value={component.status} />} />)}</dl>; }
function Latency({ latency, total }: { latency?: Record<string, number>; total?: number }) { return latency ? <div className="bars">{Object.entries(latency).map(([name, value]) => <div key={name}><div><span>{label(name)}</span><strong>{Number(value).toFixed(2)} ms</strong></div><i><b style={{ width: `${Math.min(100, (Number(value) / Math.max(...Object.values(latency))) * 100)}%` }} /></i></div>)}{total !== undefined && <p className="latency-total">Total WAF latency <strong>{total.toFixed(2)} ms</strong></p>}</div> : <p className="muted">Latency data was not retained for this event.</p>; }
function JsonDetails({ value }: { value: unknown }) { return <pre>{JSON.stringify(value, null, 2)}</pre>; }
function FeedbackForm({ event, submit }: { event: EventRecord; submit: (verdict: string, notes: string) => Promise<void> }) { const [verdict, setVerdict] = useState("CONFIRMED_ATTACK"); const [notes, setNotes] = useState(""); return <Panel title="Administrator feedback"><p className="muted">Event {event.eventId} · feedback is logged for later curation; it cannot automatically promote a model.</p><div className="form-grid"><label>Verdict<select value={verdict} onChange={(event) => setVerdict(event.target.value)}><option>CONFIRMED_ATTACK</option><option>FALSE_POSITIVE</option><option>BENIGN</option></select></label><label>Notes<input value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Reason for this verdict" /></label></div><button onClick={() => void submit(verdict, notes)}>Submit feedback</button></Panel>; }
function iconFor(section: Section) { return ({ Overview: "◫", "Live Traffic": "⌁", "Security Events": "◉", "Attack Explorer": "◌", "Request Inspector": "⌕", "Routing Explorer": "⇄", Models: "◇", "Model Versions": "◈", "Training Runs": "↗", Rules: "≡", Policies: "⌘", "Rate Limits": "⏱", "IP Management": "⊘", "Network IDS": "⌁", "Protected Applications": "▣", "Feedback Queue": "✦", "System Health": "♥", "Audit Log": "◷", Settings: "⚙" } as Record<string, string>)[section]; }
