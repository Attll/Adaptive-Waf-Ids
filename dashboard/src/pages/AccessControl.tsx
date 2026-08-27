import { useMemo, useState } from "react";
import { RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, Metric, Panel } from "../components/Ui";
import { colorFor, formatDateTime, label as humanize, milliseconds, percent, relativeTime } from "../lib/format";
import type { ViewProps } from "../lib/view";

const DURATIONS = [
  { value: "PT15M", label: "15 minutes" },
  { value: "PT1H", label: "1 hour" },
  { value: "PT6H", label: "6 hours" },
  { value: "P1D", label: "24 hours" }
];

export function AccessControl({ snapshot, api, mutate }: ViewProps) {
  const [sourceIp, setSourceIp] = useState("");
  const [reason, setReason] = useState("Operator block");
  const [duration, setDuration] = useState("PT1H");

  const blocks = snapshot.blocks;
  const activeBlocks = blocks.filter((entry) => entry.active && new Date(entry.expiresAt).getTime() > Date.now());
  const candidates = useMemo(
    () => snapshot.statistics.sources.filter((source) => source.detections > 0).slice(0, 10),
    [snapshot.statistics.sources]
  );
  const blockedSet = new Set(activeBlocks.map((entry) => entry.sourceIp));
  const valid = /^[0-9a-fA-F:.]{3,45}$/.test(sourceIp.trim());

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Active blocks" value={activeBlocks.length} detail={`${blocks.length - activeBlocks.length} expired or lifted`} tone="danger" icon={<Icon name="block" size={13} />} />
        <Metric label="Sources observed" value={snapshot.statistics.summary.uniqueSources} detail="Distinct addresses in the retained window" tone="info" icon={<Icon name="globe" size={13} />} />
        <Metric label="Offending sources" value={candidates.length} detail="Have at least one detection against them" tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Behavioural limit" value={snapshot.gatewayPolicy.rateLimitShortWindow} detail="Requests per source per short window" tone="violet" icon={<Icon name="bolt" size={13} />} />
      </div>

      <div className="grid-2">
        <Panel title="Block a source address" subtitle="Writes to the enforcement store and records the administrator action">
          <div className="form-grid">
            <label className="field">
              Source address
              <input placeholder="203.0.113.10" value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} />
            </label>
            <label className="field">
              Duration
              <select value={duration} onChange={(event) => setDuration(event.target.value)}>
                {DURATIONS.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}
              </select>
            </label>
            <label className="field" style={{ gridColumn: "span 2" }}>
              Audit reason
              <input value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
          </div>
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button
              className="btn danger"
              disabled={!valid}
              onClick={() => void mutate(() => api.block(sourceIp.trim(), reason, duration), `${sourceIp.trim()} blocked for ${DURATIONS.find((entry) => entry.value === duration)?.label}.`)}
            >
              <Icon name="block" size={13} />
              Block source
            </button>
            <button
              className="btn"
              disabled={!valid}
              onClick={() => void mutate(() => api.unblock(sourceIp.trim()), `${sourceIp.trim()} is no longer blocked.`)}
            >
              Lift block
            </button>
          </div>
          <p className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>
            A manual block affects enforcement only. It does not change model behaviour or the risk threshold.
          </p>
        </Panel>

        <Panel title="Suggested blocks" subtitle="Sources with recorded detections, ranked by attack volume">
          {candidates.length ? (
            <div className="stack" style={{ gap: 8 }}>
              {candidates.map((source) => (
                <div className="probe-row" key={source.sourceIp}>
                  <span className="dot" style={{ background: source.maxRisk >= 0.81 ? "var(--danger)" : "var(--warning)" }} />
                  <div>
                    <div className="mono" style={{ fontSize: 12.5, color: "var(--text)" }}>{source.sourceIp}</div>
                    <div className="muted" style={{ fontSize: 11 }}>
                      {source.detections} detections · {source.blocked} blocked · peak {percent(source.maxRisk, 0)} ·{" "}
                      {Object.keys(source.attacks).slice(0, 2).map(humanize).join(", ")}
                    </div>
                  </div>
                  {blockedSet.has(source.sourceIp) ? (
                    <Badge value="BLOCKED" tone="danger" />
                  ) : (
                    <button
                      className="btn small"
                      onClick={() => { setSourceIp(source.sourceIp); setReason(`Automated detections from ${source.sourceIp}`); }}
                    >
                      Select
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No offending sources" detail="Sources appear here once the pipeline classifies traffic from them as an attack." icon={<Icon name="globe" />} />
          )}
        </Panel>
      </div>

      <Panel title="Enforcement list" subtitle="Every manual block recorded by the control plane" flush>
        {blocks.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Source</th><th>State</th><th>Reason</th><th>Expires</th><th>Observed traffic</th><th></th></tr></thead>
              <tbody>
                {blocks.map((entry) => {
                  const expired = new Date(entry.expiresAt).getTime() <= Date.now();
                  const profile = snapshot.statistics.sources.find((source) => source.sourceIp === entry.sourceIp);
                  return (
                    <tr key={entry.sourceIp}>
                      <td className="mono cell-strong">{entry.sourceIp}</td>
                      <td><Badge value={!entry.active ? "LIFTED" : expired ? "EXPIRED" : "ACTIVE"} tone={!entry.active || expired ? "neutral" : "danger"} /></td>
                      <td className="muted">{entry.reason}</td>
                      <td className="mono muted">{formatDateTime(entry.expiresAt)}<span className="cell-sub">{relativeTime(entry.expiresAt)}</span></td>
                      <td>
                        {profile ? (
                          <div className="chip-row">
                            <span className="chip">{profile.requests} requests</span>
                            <span className="chip">{profile.detections} detections</span>
                            <span className="chip">{milliseconds(profile.meanLatencyMs, 1)}</span>
                          </div>
                        ) : (
                          <span className="muted">Not seen in the retained window</span>
                        )}
                      </td>
                      <td className="actions">
                        {entry.active && !expired && (
                          <button className="btn small" onClick={() => void mutate(() => api.unblock(entry.sourceIp), `${entry.sourceIp} is no longer blocked.`)}>Lift</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No blocks recorded" detail="Blocked addresses appear here after an operator adds one." icon={<Icon name="block" />} />
        )}
      </Panel>

      <Panel title="Traffic by source" subtitle="Volume across the retained window">
        <RankedBars
          data={snapshot.statistics.sources.slice(0, 12).map((source) => ({ label: source.sourceIp, value: source.requests }))}
          colorKey={(name) => (blockedSet.has(name) ? "#ff5c5c" : colorFor(name))}
        />
      </Panel>
    </div>
  );
}
