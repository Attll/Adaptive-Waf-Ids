import { useMemo, useState } from "react";
import { RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Switch } from "../components/Ui";
import { label as humanize, milliseconds, percent, shortId } from "../lib/format";
import type { ViewProps } from "../lib/view";

export function Applications({ snapshot, api, mutate }: ViewProps) {
  const [name, setName] = useState("");
  const [upstreamUrl, setUpstreamUrl] = useState("http://127.0.0.1:8081");
  const [creating, setCreating] = useState(false);

  const enabled = snapshot.applications.filter((app) => app.enabled).length;
  const perEndpoint = useMemo(
    () => Object.entries(snapshot.statistics.byEndpoint).map(([endpoint, count]) => ({ label: endpoint, value: count })),
    [snapshot.statistics.byEndpoint]
  );
  const upstreamLatency = snapshot.statistics.summary.upstreamLatencyMeanMs;

  const validUrl = /^https?:\/\/.+/.test(upstreamUrl.trim());

  const create = async () => {
    setCreating(true);
    await mutate(() => api.createApplication(name.trim(), upstreamUrl.trim()), `${name.trim()} registered for gateway protection.`);
    setName("");
    setCreating(false);
  };

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Registered" value={snapshot.applications.length} detail={`${enabled} currently protected`} tone="info" icon={<Icon name="apps" size={13} />} />
        <Metric label="Endpoints seen" value={Object.keys(snapshot.statistics.byEndpoint).length} detail="Distinct method and path pairs" tone="violet" icon={<Icon name="requests" size={13} />} />
        <Metric label="Mean upstream latency" value={milliseconds(upstreamLatency, 2)} detail="Time spent inside the protected application" tone="success" icon={<Icon name="clock" size={13} />} />
        <Metric label="Requests reaching upstream" value={snapshot.statistics.summary.total - snapshot.statistics.summary.blocked} detail={`${percent(snapshot.statistics.summary.total ? snapshot.statistics.summary.blocked / snapshot.statistics.summary.total : 0, 1)} rejected first`} tone="warning" icon={<Icon name="shield" size={13} />} />
      </div>

      <Panel title="Protected application registry" subtitle="Toggling protection is recorded in the audit log">
        {snapshot.applications.length ? (
          <div className="grid-2">
            {snapshot.applications.map((app) => (
              <article className="stage-card" key={app.applicationId}>
                <header>
                  <span className={`dot ${app.enabled ? "success" : "neutral"}`} />
                  <h3>{app.name}</h3>
                  <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 9 }}>
                    <Badge value={app.enabled ? "PROTECTED" : "DISABLED"} tone={app.enabled ? "success" : "neutral"} />
                    <Switch
                      checked={app.enabled}
                      label={`Protection for ${app.name}`}
                      onChange={(next) =>
                        void mutate(
                          () => api.setApplicationEnabled(app.applicationId, next),
                          `${app.name} ${next ? "enabled" : "disabled"} for gateway protection.`
                        )
                      }
                    />
                  </span>
                </header>
                <dl className="kv-list">
                  <KV k="Upstream" v={<span className="mono">{app.upstreamUrl}</span>} />
                  <KV k="Application id" v={<span className="mono faint">{shortId(app.applicationId, 18)}</span>} />
                  <KV k="Requests observed" v={String(snapshot.statistics.summary.total)} />
                </dl>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="No applications registered" detail="Register an upstream below to place it behind the gateway." icon={<Icon name="apps" />} />
        )}
      </Panel>

      <div className="grid-2">
        <Panel title="Register an application" subtitle="The gateway proxies matched traffic to this upstream">
          <div className="form-grid">
            <label className="field">
              Name
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="checkout-service" />
            </label>
            <label className="field">
              Upstream URL
              <input value={upstreamUrl} onChange={(event) => setUpstreamUrl(event.target.value)} placeholder="http://127.0.0.1:8081" />
            </label>
          </div>
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button className="btn primary" disabled={!name.trim() || !validUrl || creating} onClick={() => void create()}>
              {creating ? <span className="spinner" /> : <Icon name="check" size={13} />}
              Register
            </button>
          </div>
          {!validUrl && upstreamUrl.trim() && (
            <p style={{ marginTop: 10, fontSize: 11.5, color: "var(--warning)" }}>The upstream must be an absolute http or https URL.</p>
          )}
        </Panel>

        <Panel title="Endpoint traffic" subtitle="Where requests are landing across the protected surface">
          <RankedBars data={perEndpoint.slice(0, 10)} />
        </Panel>
      </div>

      <Panel title="Mitigation by outcome" subtitle="How the gateway resolved traffic aimed at these applications">
        <RankedBars
          data={Object.entries(snapshot.statistics.byMitigation).map(([name, value]) => ({ label: humanize(name), value }))}
          colorKey={(entry) => (entry.toLowerCase().includes("block") || entry.toLowerCase().includes("rate") ? "#ff5c5c" : "#2bd576")}
        />
      </Panel>
    </div>
  );
}
