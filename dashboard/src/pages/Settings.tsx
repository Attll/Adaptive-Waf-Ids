import { Badge, Icon, KV, Panel, Segmented, Switch } from "../components/Ui";
import { formatDateTime, label as humanize, relativeTime } from "../lib/format";
import type { ViewProps } from "../lib/view";

const INTERVALS = [
  { value: "5", label: "5s" },
  { value: "15", label: "15s" },
  { value: "60", label: "60s" },
  { value: "0", label: "Off" }
];

export function SettingsPage({
  username,
  signOut,
  stream,
  streamEnabled,
  setStreamEnabled,
  refreshInterval,
  setRefreshInterval,
  snapshot,
  refresh,
  notify
}: ViewProps) {
  return (
    <div className="stack">
      <div className="grid-2">
        <Panel title="Session">
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 16 }}>
            <span
              style={{
                display: "grid", placeItems: "center", width: 42, height: 42, borderRadius: "50%",
                background: "linear-gradient(135deg, var(--accent), var(--violet))", color: "#fff",
                fontSize: 17, fontWeight: 600
              }}
            >
              {username.slice(0, 1).toUpperCase()}
            </span>
            <div>
              <strong style={{ fontSize: 14 }}>{username}</strong>
              <p className="muted" style={{ fontSize: 12 }}>Administrator · authenticated against the control plane</p>
            </div>
          </div>
          <div className="btn-row">
            <button className="btn" onClick={signOut}>Sign out</button>
            <button className="btn ghost" onClick={() => void refresh()}>
              <Icon name="refresh" size={13} />
              Force refresh
            </button>
          </div>
          <p className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>
            Credentials stay in memory for this tab only and are never written to browser storage.
          </p>
        </Panel>

        <Panel title="Live data" subtitle="How this console keeps itself current">
          <div className="stack" style={{ gap: 16 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 11, fontSize: 12.5 }}>
              <Switch checked={streamEnabled} onChange={(next) => {
                setStreamEnabled(next);
                notify(next ? "Live stream enabled" : "Live stream disabled", next ? "Decisions will be pushed as they are journalled." : "The console will rely on polling.", next ? "success" : "warning");
              }} label="Live event stream" />
              <span>
                Push decisions over WebSocket
                <span className="cell-sub">Falls back to polling automatically when the socket cannot connect</span>
              </span>
            </label>

            <div>
              <p style={{ fontSize: 12.5, marginBottom: 8 }}>Snapshot poll interval</p>
              <Segmented
                value={String(refreshInterval)}
                onChange={(next) => setRefreshInterval(Number(next))}
                options={INTERVALS}
              />
            </div>

            <dl className="kv-list">
              <KV k="Stream state" v={<Badge value={stream.state} tone={stream.state === "live" ? "success" : stream.state === "offline" ? "neutral" : "warning"} />} />
              <KV k="Events pushed" v={String(stream.received)} />
              <KV k="Last push" v={stream.lastEventAt ? `${formatDateTime(stream.lastEventAt)} · ${relativeTime(stream.lastEventAt)}` : "None yet"} />
            </dl>
          </div>
        </Panel>
      </div>

      <Panel title="Connected services" subtitle="Where this console reads and writes">
        <dl className="kv-list">
          <KV k="Traffic and enforcement" v={<span className="mono">/gateway-api → :8080</span>} />
          <KV k="Inference runtime" v={<span className="mono">/detection-api → :8000</span>} />
          <KV k="Governance and journal" v={<span className="mono">/control-api → :8082</span>} />
          <KV k="Live event stream" v={<span className="mono">/control-ws/v1/stream/events</span>} />
          <KV k="Network context" v={<span className="mono">/sensor-api → :8083</span>} />
          <KV k="Training lifecycle" v={<span className="mono">/adaptation-api → :8084</span>} />
        </dl>
      </Panel>

      <Panel title="Current state" subtitle="What the console is holding right now">
        <dl className="kv-list">
          <KV k="Retained requests" v={String(snapshot.events.length)} />
          <KV k="Registered models" v={String(snapshot.models.length)} />
          <KV k="Training runs" v={String(snapshot.trainingRuns.length)} />
          <KV k="Reviews submitted" v={String(snapshot.feedback.length)} />
          <KV k="Active blocks" v={String(snapshot.blocks.filter((entry) => entry.active).length)} />
          <KV k="Gateway mode" v={<Badge value={snapshot.mode.mode} />} />
          <KV k="Runtime models" v={Object.entries(snapshot.runtimeModels.models).map(([role]) => humanize(role)).join(", ") || "None reported"} />
        </dl>
      </Panel>
    </div>
  );
}
