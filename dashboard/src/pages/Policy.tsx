import { useEffect, useMemo, useState } from "react";
import { AreaChart, RadialGauge } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Slider } from "../components/Ui";
import { formatTime, isDetection, milliseconds, percent } from "../lib/format";
import type { ViewProps } from "../lib/view";

export function PolicyPage({ snapshot, api, mutate }: ViewProps) {
  const [threshold, setThreshold] = useState(snapshot.policy.blockRiskThreshold);
  const [limit, setLimit] = useState(snapshot.policy.rateLimitShortWindow);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setThreshold(snapshot.policy.blockRiskThreshold);
    setLimit(snapshot.policy.rateLimitShortWindow);
  }, [snapshot.policy]);

  const dirty = threshold !== snapshot.policy.blockRiskThreshold || limit !== snapshot.policy.rateLimitShortWindow;
  const synchronized =
    snapshot.policy.version === snapshot.gatewayPolicy.version &&
    snapshot.policy.blockRiskThreshold === snapshot.gatewayPolicy.blockRiskThreshold &&
    snapshot.policy.rateLimitShortWindow === snapshot.gatewayPolicy.rateLimitShortWindow;

  /** Replays the retained window against the proposed threshold so the operator sees the effect before saving. */
  const impact = useMemo(() => {
    const events = snapshot.events;
    const wouldBlock = events.filter((event) => event.risk > threshold).length;
    const currentlyBlocked = events.filter((event) => event.action === "BLOCK").length;
    const detections = events.filter(isDetection).length;
    const missed = events.filter((event) => isDetection(event) && event.risk <= threshold).length;
    const benignCaught = events.filter((event) => !isDetection(event) && event.risk > threshold).length;
    return { wouldBlock, currentlyBlocked, detections, missed, benignCaught, total: events.length };
  }, [snapshot.events, threshold]);

  const distribution = useMemo(() => {
    const buckets = new Array(20).fill(0);
    snapshot.events.forEach((event) => {
      const index = Math.min(19, Math.max(0, Math.floor(event.risk * 20)));
      buckets[index] += 1;
    });
    return buckets;
  }, [snapshot.events]);

  const save = async () => {
    setSaving(true);
    await mutate(
      () => api.updatePolicy({ blockRiskThreshold: threshold, rateLimitShortWindow: limit }),
      `Policy version ${snapshot.policy.version + 1} saved and queued for gateway refresh.`
    );
    setSaving(false);
  };

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Authoritative version" value={`v${snapshot.policy.version}`} detail="Immutable, stored by the control plane" tone="info" icon={<Icon name="policy" size={13} />} />
        <Metric label="Gateway applied" value={`v${snapshot.gatewayPolicy.version}`} detail={synchronized ? "In sync with the control plane" : "Refresh pending"} tone={synchronized ? "success" : "warning"} icon={<Icon name="refresh" size={13} />} />
        <Metric label="Block threshold" value={percent(snapshot.gatewayPolicy.blockRiskThreshold, 0)} detail="Fused risk above this is rejected" tone="danger" icon={<Icon name="shield" size={13} />} />
        <Metric label="Short-window limit" value={snapshot.gatewayPolicy.rateLimitShortWindow} detail="Requests per source per short window" tone="violet" icon={<Icon name="bolt" size={13} />} />
      </div>

      <div className="grid-2">
        <Panel
          title="Enforcement policy"
          subtitle="Saving creates a new immutable version; the gateway refreshes its cache independently"
          action={dirty ? <Badge value="UNSAVED" tone="warning" /> : <Badge value={`VERSION ${snapshot.policy.version}`} tone="neutral" />}
        >
          <div className="stack" style={{ gap: 20 }}>
            <Slider
              label="Block-risk threshold"
              value={threshold}
              min={0}
              max={1}
              step={0.01}
              format={(value) => `${(value * 100).toFixed(0)}%`}
              onChange={setThreshold}
            />
            <Slider
              label="Short-window request limit"
              value={limit}
              min={1}
              max={500}
              step={1}
              format={(value) => `${value} requests`}
              onChange={setLimit}
            />
            <div className="btn-row">
              <button className="btn primary" onClick={() => void save()} disabled={!dirty || saving}>
                {saving ? <span className="spinner" /> : <Icon name="check" size={13} />}
                {saving ? "Saving" : "Save new version"}
              </button>
              <button className="btn ghost" onClick={() => { setThreshold(snapshot.policy.blockRiskThreshold); setLimit(snapshot.policy.rateLimitShortWindow); }} disabled={!dirty}>
                Reset
              </button>
            </div>
          </div>
        </Panel>

        <Panel title="Projected effect" subtitle="The retained window replayed against the proposed threshold">
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center", marginBottom: 14 }}>
            <RadialGauge value={impact.total ? impact.wouldBlock / impact.total : 0} label="would block" color="#ff5c5c" />
            <RadialGauge value={impact.detections ? 1 - impact.missed / impact.detections : 1} label="attacks caught" color="#2bd576" />
          </div>
          <dl className="kv-list">
            <KV k="Requests in window" v={String(impact.total)} />
            <KV k="Would be blocked" v={<strong>{impact.wouldBlock}</strong>} />
            <KV k="Currently blocked" v={String(impact.currentlyBlocked)} />
            <KV k="Detections missed at this threshold" v={<span style={{ color: impact.missed ? "var(--warning)" : undefined }}>{impact.missed}</span>} />
            <KV k="Benign traffic caught" v={<span style={{ color: impact.benignCaught ? "var(--danger)" : undefined }}>{impact.benignCaught}</span>} />
            <KV k="Change from applied policy" v={`${impact.wouldBlock - impact.currentlyBlocked >= 0 ? "+" : ""}${impact.wouldBlock - impact.currentlyBlocked} blocks`} />
          </dl>
        </Panel>
      </div>

      <Panel title="Risk distribution" subtitle="Every retained request bucketed by fused risk; the marker shows the proposed threshold">
        {snapshot.events.length ? (
          <div style={{ position: "relative" }}>
            <AreaChart
              labels={distribution.map((_, index) => `${index * 5}%`)}
              height={190}
              series={[{ name: "Requests", color: "#3b82f6", values: distribution }]}
            />
            <div
              style={{
                position: "absolute",
                top: 10,
                bottom: 46,
                left: `calc(${5.5 + threshold * 89}%)`,
                borderLeft: "1px dashed var(--danger)",
                pointerEvents: "none"
              }}
            >
              <span style={{ position: "absolute", top: -2, left: 6, fontSize: 10.5, color: "var(--danger)", whiteSpace: "nowrap" }}>
                block above {percent(threshold, 0)}
              </span>
            </div>
          </div>
        ) : (
          <EmptyState title="No traffic retained" detail="Send requests through the gateway to populate the distribution." icon={<Icon name="activity" />} />
        )}
      </Panel>

      <div className="grid-2">
        <Panel title="Gateway enforcement cache" action={<Badge value={synchronized ? "SYNCHRONIZED" : "PENDING"} tone={synchronized ? "success" : "warning"} />}>
          <dl className="kv-list">
            <KV k="Applied version" v={`v${snapshot.gatewayPolicy.version}`} />
            <KV k="Applied threshold" v={percent(snapshot.gatewayPolicy.blockRiskThreshold, 0)} />
            <KV k="Applied short-window limit" v={`${snapshot.gatewayPolicy.rateLimitShortWindow} requests`} />
            <KV k="Operating mode" v={<Badge value={snapshot.mode.mode} />} />
            <KV k="Mean decision latency" v={milliseconds(snapshot.statistics.summary.detectionLatencyMeanMs, 2)} />
          </dl>
          <p className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>
            The gateway polls the control plane on its own refresh interval, so a newly saved version can show as pending for a few seconds.
          </p>
        </Panel>
        <Panel title="Enforcement over time" subtitle="Blocked requests per minute in the retained window">
          <AreaChart
            labels={snapshot.statistics.timeline.map((point) => formatTime(point.bucket).slice(0, 5))}
            height={170}
            series={[{ name: "Blocked", color: "#ff5c5c", values: snapshot.statistics.timeline.map((point) => point.blocked) }]}
          />
        </Panel>
      </div>
    </div>
  );
}
