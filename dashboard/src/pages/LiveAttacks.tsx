import { useMemo, useState } from "react";
import type { EventRecord } from "../api";
import { AreaChart, DonutChart, RankedBars } from "../components/Charts";
import { buildFlow, RequestFlow } from "../components/RequestFlow";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Segmented, Switch } from "../components/Ui";
import {
  colorFor,
  formatTime,
  isDetection,
  label as humanize,
  milliseconds,
  MITIGATION_COPY,
  parseJson,
  percent,
  relativeTime,
  sortedEntries
} from "../lib/format";
import { useDetectionEvidence } from "../lib/useDetectionEvidence";
import type { ViewProps } from "../lib/view";

type Window = "all" | "5" | "15" | "60";

export function LiveAttacks(props: ViewProps) {
  const { snapshot, selected, select, liveIds, stream, streamEnabled, setStreamEnabled, goTo } = props;
  const [window, setWindow] = useState<Window>("all");
  const [onlyBlocked, setOnlyBlocked] = useState(false);

  const attacks = useMemo(() => {
    const cutoff = window === "all" ? 0 : Date.now() - Number(window) * 60_000;
    return snapshot.events
      .filter(isDetection)
      .filter((event) => new Date(event.occurredAt).getTime() >= cutoff)
      .filter((event) => !onlyBlocked || event.action === "BLOCK");
  }, [snapshot.events, window, onlyBlocked]);

  const active = attacks.find((event) => event.eventId === selected?.eventId) ?? attacks[0];
  const detection = useDetectionEvidence(active);
  const flow = useMemo(() => buildFlow(active, detection), [active, detection]);

  const blocked = attacks.filter((event) => event.action === "BLOCK").length;
  const escalated = attacks.filter((event) => event.deepModelUsed).length;
  const meanLatency = average(attacks.map((event) => event.gatewayLatencyMs).filter((value) => value > 0));
  const meanConfidence = average(attacks.map((event) => event.confidence).filter((value) => value > 0));

  const byAttack = useMemo(() => tally(attacks, (event) => event.predictedAttack ?? "UNKNOWN"), [attacks]);
  const bySource = useMemo(() => tally(attacks, (event) => event.sourceIp ?? "unknown"), [attacks]);
  const byEndpoint = useMemo(() => tally(attacks, (event) => `${event.method} ${event.path}`), [attacks]);
  const byMitigation = useMemo(() => tally(attacks, (event) => event.mitigation ?? "UNKNOWN"), [attacks]);
  const timeline = snapshot.statistics.timeline;

  return (
    <div className="stack">
      <div className="toolbar">
        <Segmented<Window>
          value={window}
          onChange={setWindow}
          options={[
            { value: "5", label: "5m" },
            { value: "15", label: "15m" },
            { value: "60", label: "1h" },
            { value: "all", label: "All" }
          ]}
        />
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--text-secondary)" }}>
          <Switch checked={onlyBlocked} onChange={setOnlyBlocked} label="Only blocked" />
          Blocked only
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--text-secondary)" }}>
          <Switch checked={streamEnabled} onChange={setStreamEnabled} label="Live stream" />
          Live stream
        </label>
        <span className="toolbar-count" style={{ marginLeft: "auto" }}>
          {attacks.length} detections · {stream.received} pushed
          {stream.lastEventAt && ` · last ${relativeTime(stream.lastEventAt)}`}
        </span>
      </div>

      <div className="grid-4 stagger">
        <Metric label="Detections in view" value={attacks.length} detail={`${blocked} blocked at the gateway`} tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Deep escalations" value={escalated} detail="Low-confidence expert output adjudicated" tone="violet" icon={<Icon name="layers" size={13} />} />
        <Metric label="Mean decision latency" value={milliseconds(meanLatency, 1)} detail="Ingress to response, gateway measured" tone="info" icon={<Icon name="clock" size={13} />} />
        <Metric label="Mean confidence" value={percent(meanConfidence, 1)} detail="Confidence of the deciding stage" tone="success" icon={<Icon name="check" size={13} />} />
      </div>

      <Panel title="Attack volume" subtitle="Detections and blocks per minute across the retained window">
        <AreaChart
          labels={timeline.map((point) => formatTime(point.bucket).slice(0, 5))}
          height={180}
          series={[
            { name: "Detections", color: "#f5a524", values: timeline.map((point) => point.detections) },
            { name: "Blocked", color: "#ff5c5c", values: timeline.map((point) => point.blocked) }
          ]}
        />
      </Panel>

      <div className="split">
        <Panel title="Attack feed" subtitle="Newest first, pushed over the live stream" tight>
          {attacks.length ? (
            <div className="live-feed">
              {attacks.map((event) => (
                <article
                  key={event.eventId}
                  className={`live-card${active?.eventId === event.eventId ? " selected" : ""}`}
                  onClick={() => select(event)}
                  style={liveIds.has(event.eventId) ? { borderColor: "var(--accent-line)" } : undefined}
                >
                  <div className="top">
                    <span className="dot" style={{ background: colorFor(event.predictedAttack ?? "UNKNOWN") }} />
                    <strong style={{ fontSize: 12 }}>{humanize(event.predictedAttack ?? "UNKNOWN")}</strong>
                    <Badge value={event.action} />
                    <span className="when">{formatTime(event.occurredAt)}</span>
                  </div>
                  <div className="target">{event.method} {event.path}{event.query ? `?${event.query}` : ""}</div>
                  <div className="facts">
                    <span>from <b>{event.sourceIp ?? "unknown"}</b></span>
                    <span>risk <b>{percent(event.risk, 1)}</b></span>
                    <span>confidence <b>{percent(event.confidence, 1)}</b></span>
                    <span>latency <b>{milliseconds(event.gatewayLatencyMs, 1)}</b></span>
                    <span>HTTP <b>{event.statusCode}</b></span>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState title="No detections in this window" detail="Widen the window, or replay attack payloads from the Models page." icon={<Icon name="shield" />} />
          )}
        </Panel>

        <div className="stack">
          {active ? (
            <>
              <Panel
                title="How this request was handled"
                subtitle={MITIGATION_COPY[active.mitigation ?? ""] ?? "Decision recorded by the gateway"}
                action={<Badge value={active.action} />}
              >
                <div className="grid-3" style={{ gap: 12, marginBottom: 14 }}>
                  <Metric label="Classification" value={humanize(active.predictedAttack ?? "UNKNOWN")} detail={`${percent(active.risk, 2)} fused risk`} tone="danger" />
                  <Metric label="Decision latency" value={milliseconds(active.gatewayLatencyMs, 2)} detail={`${milliseconds(active.detectionLatencyMs, 2)} inference`} tone="info" />
                  <Metric label="Upstream" value={active.upstreamLatencyMs > 0 ? milliseconds(active.upstreamLatencyMs, 2) : "Not reached"} detail={active.upstream ?? "Demo backend"} tone={active.upstreamLatencyMs > 0 ? "success" : "neutral"} />
                </div>
                <RequestFlow nodes={flow} />
              </Panel>

              <div className="grid-2">
                <Panel title="Request identity">
                  <dl className="kv-list">
                    <KV k="Source address" v={<span className="mono">{active.sourceIp ?? "not recorded"}</span>} />
                    <KV k="Request id" v={<span className="mono">{active.requestId ?? "—"}</span>} />
                    <KV k="Target" v={<span className="mono">{active.method} {active.path}</span>} />
                    <KV k="Query" v={<span className="mono">{active.query || "—"}</span>} />
                    <KV k="User agent" v={<span className="mono">{active.userAgent ?? "—"}</span>} />
                    <KV k="Gateway mode" v={<Badge value={active.mode} />} />
                    <KV k="Observed" v={`${formatTime(active.occurredAt)} · ${relativeTime(active.occurredAt)}`} />
                  </dl>
                </Panel>
                <Panel title="Models consulted" subtitle="Version of every artifact that ran">
                  {detection ? (
                    <dl className="kv-list">
                      {Object.entries(detection.model_versions).map(([role, version]) => (
                        <KV key={role} k={humanize(role)} v={<span className="mono">{version}</span>} />
                      ))}
                    </dl>
                  ) : (
                    <EmptyState title="No inference evidence" detail="This decision was recorded without per-stage evidence, which happens when detection was skipped or unavailable." icon={<Icon name="models" />} />
                  )}
                </Panel>
              </div>

              <Panel title="Full decision record" subtitle="Sanitized event as persisted by the control plane" action={
                <button className="link-btn" onClick={() => { select(active); goTo("Request Visualizer"); }}>Open in visualizer</button>
              }>
                <pre className="code-block">{JSON.stringify(parseJson(active.detailsJson), null, 2)}</pre>
              </Panel>
            </>
          ) : (
            <Panel title="Attack detail">
              <EmptyState title="Nothing selected" detail="Choose an entry from the attack feed to see how it was routed and mitigated." icon={<Icon name="flow" />} />
            </Panel>
          )}
        </div>
      </div>

      <div className="grid-3">
        <Panel title="By classification">
          <DonutChart data={sortedEntries(byAttack).map(([name, value]) => ({ label: humanize(name), value }))} centerLabel="detections" size={140} />
        </Panel>
        <Panel title="By source address">
          <RankedBars data={sortedEntries(bySource).slice(0, 8).map(([name, value]) => ({ label: name, value }))} />
        </Panel>
        <Panel title="By endpoint">
          <RankedBars data={sortedEntries(byEndpoint).slice(0, 8).map(([name, value]) => ({ label: name, value }))} />
        </Panel>
      </div>

      <Panel title="Mitigation applied" subtitle="Every outcome recorded for detections in this window">
        <RankedBars
          data={sortedEntries(byMitigation).map(([name, value]) => ({ label: humanize(name), value }))}
          colorKey={(name) => (name.toLowerCase().includes("block") || name.toLowerCase().includes("rate") ? "#ff5c5c" : "#f5a524")}
        />
      </Panel>
    </div>
  );
}

function tally(events: EventRecord[], key: (event: EventRecord) => string): Record<string, number> {
  return events.reduce<Record<string, number>>((result, event) => {
    const name = key(event);
    result[name] = (result[name] ?? 0) + 1;
    return result;
  }, {});
}

function average(values: number[]): number {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}
