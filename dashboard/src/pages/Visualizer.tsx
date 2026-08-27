import { useMemo, useState } from "react";
import { DonutChart, RankedBars } from "../components/Charts";
import { EventTable } from "../components/EventTable";
import { buildFlow, RequestFlow } from "../components/RequestFlow";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Tabs } from "../components/Ui";
import {
  colorFor,
  formatDateTime,
  label as humanize,
  milliseconds,
  MITIGATION_COPY,
  parseJson,
  percent,
  STAGE_COPY
} from "../lib/format";
import { useDetectionEvidence } from "../lib/useDetectionEvidence";
import type { ViewProps } from "../lib/view";

type Tab = "flow" | "stages" | "scores" | "evidence" | "raw";

export function Visualizer(props: ViewProps) {
  const { snapshot, selected, select, liveIds } = props;
  const [tab, setTab] = useState<Tab>("flow");
  const active = selected ?? snapshot.events[0];
  const detection = useDetectionEvidence(active);
  const flow = useMemo(() => buildFlow(active, detection), [active, detection]);

  const stageLatency = detection?.latency_by_stage_ms ?? {};
  const stageEntries = Object.entries(stageLatency).sort(([, first], [, second]) => second - first);
  const inferenceTotal = detection?.total_latency_ms ?? 0;

  if (!active) {
    return (
      <Panel title="Request visualizer">
        <EmptyState title="No requests retained" detail="Send traffic through the gateway to populate the journal." icon={<Icon name="flow" />} />
      </Panel>
    );
  }

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Decision" value={humanize(active.predictedAttack ?? "UNKNOWN")} detail={`${humanize(active.action ?? "")} · HTTP ${active.statusCode}`} tone={active.action === "BLOCK" ? "danger" : "success"} icon={<Icon name="shield" size={13} />} />
        <Metric label="Fused risk" value={percent(active.risk, 2)} detail={`confidence ${percent(active.confidence, 1)}`} tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Inference" value={milliseconds(inferenceTotal || active.detectionLatencyMs, 2)} detail={`${stageEntries.length} stages timed`} tone="violet" icon={<Icon name="bolt" size={13} />} />
        <Metric label="End to end" value={milliseconds(active.gatewayLatencyMs, 2)} detail={active.upstreamLatencyMs > 0 ? `upstream ${milliseconds(active.upstreamLatencyMs, 2)}` : "upstream not reached"} tone="info" icon={<Icon name="clock" size={13} />} />
      </div>

      <Panel
        title="Request journey"
        subtitle={MITIGATION_COPY[active.mitigation ?? ""] ?? "How this request moved through the platform"}
        action={<Badge value={active.action} />}
      >
        <RequestFlow nodes={flow} />
      </Panel>

      <section className="panel">
        <Tabs<Tab>
          value={tab}
          onChange={setTab}
          options={[
            { value: "flow", label: "Timing" },
            { value: "stages", label: "Stage detail" },
            { value: "scores", label: "Class scores" },
            { value: "evidence", label: "Context" },
            { value: "raw", label: "Raw record" }
          ]}
        />
        <div className="panel-body">
          {tab === "flow" && (
            <div className="grid-2">
              <div>
                <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>
                  Time spent inside each pipeline stage for this request.
                </p>
                {stageEntries.length ? (
                  <RankedBars
                    data={stageEntries.map(([stage, value]) => ({ label: STAGE_COPY[stage]?.title ?? humanize(stage), value: Number(value.toFixed(3)) }))}
                    format={(value) => `${value.toFixed(3)} ms`}
                    colorKey={(name) => colorFor(name)}
                  />
                ) : (
                  <EmptyState title="No per-stage timing" detail="Timing appears when the gateway retains inference evidence with the event." icon={<Icon name="clock" />} />
                )}
              </div>
              <div>
                <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>Where the wall-clock time went end to end.</p>
                <DonutChart
                  size={150}
                  centerLabel="ms"
                  data={[
                    { label: "Inference", value: Number((inferenceTotal || active.detectionLatencyMs).toFixed(2)) },
                    { label: "Upstream", value: Number(active.upstreamLatencyMs.toFixed(2)) },
                    {
                      label: "Gateway overhead",
                      value: Number(Math.max(0, active.gatewayLatencyMs - active.detectionLatencyMs - active.upstreamLatencyMs).toFixed(2))
                    }
                  ].filter((entry) => entry.value > 0)}
                />
              </div>
            </div>
          )}

          {tab === "stages" && (
            detection ? (
              <div className="grid-3">
                <StageCard
                  title="Triage"
                  verdict={humanize(detection.triage.decision)}
                  model={detection.model_versions.triage}
                  metrics={[
                    ["Suspicious", percent(detection.triage.suspicious_probability, 3)],
                    ["Latency", milliseconds(stageLatency.triage, 3)],
                    ["Outcome", detection.router ? "Escalated" : "Early exit"]
                  ]}
                />
                <StageCard
                  title="Router"
                  verdict={detection.router ? detection.router.selected_experts.map(humanize).join(" + ") : "Not reached"}
                  model={detection.model_versions.router}
                  metrics={[
                    ["Latency", milliseconds(stageLatency.router, 3)],
                    ["Experts", String(detection.router?.selected_experts.length ?? 0)],
                    ["Mode", (detection.router?.selected_experts.length ?? 0) > 1 ? "Top-2" : "Top-1"]
                  ]}
                />
                {detection.expert_outputs.map((output, index) => (
                  <StageCard
                    key={`${output.model_version}-${index}`}
                    title={`Fast expert ${index + 1}`}
                    verdict={humanize(output.predicted_attack)}
                    model={output.model_version}
                    metrics={[
                      ["Confidence", percent(output.confidence, 3)],
                      ["Risk", percent(output.risk, 3)],
                      ["Classes", String(Object.keys(output.class_scores ?? {}).length)]
                    ]}
                  />
                ))}
                <StageCard
                  title="Deep escalation"
                  verdict={detection.deep_output ? humanize(detection.deep_output.predicted_attack) : "Not escalated"}
                  model={detection.deep_output?.model_version ?? detection.model_versions.deep}
                  metrics={[
                    ["Confidence", detection.deep_output ? percent(detection.deep_output.confidence, 3) : "—"],
                    ["Latency", milliseconds(stageLatency.deep, 3)],
                    ["Used", detection.deep_model_used ? "Yes" : "No"]
                  ]}
                />
                <StageCard
                  title="Risk fusion"
                  verdict={percent(detection.risks.overall, 3)}
                  model="deterministic weighted-max"
                  metrics={[
                    ["HTTP", percent(detection.risks.http, 2)],
                    ["Behaviour", percent(detection.risks.behaviour, 2)],
                    ["Network", percent(detection.risks.network, 2)]
                  ]}
                />
              </div>
            ) : (
              <EmptyState title="No stage evidence retained" detail="This event records the final decision only, which happens when inference was skipped or the detection service was unavailable." icon={<Icon name="layers" />} />
            )
          )}

          {tab === "scores" && (
            detection ? (
              <div className="grid-2">
                {detection.router && (
                  <div>
                    <h3 style={{ fontSize: 12.5, marginBottom: 10 }}>Router family scores</h3>
                    <RankedBars
                      data={Object.entries(detection.router.scores).map(([family, score]) => ({ label: humanize(family), value: Number(score.toFixed(4)) }))}
                      format={(value) => percent(value, 2)}
                    />
                  </div>
                )}
                {detection.expert_outputs.map((output, index) => (
                  <div key={index}>
                    <h3 style={{ fontSize: 12.5, marginBottom: 10 }}>Expert {index + 1} class scores</h3>
                    <RankedBars
                      data={Object.entries(output.class_scores ?? {}).map(([name, score]) => ({ label: humanize(name), value: Number(Number(score).toFixed(4)) }))}
                      format={(value) => percent(value, 2)}
                    />
                  </div>
                ))}
                {detection.deep_output && (
                  <div>
                    <h3 style={{ fontSize: 12.5, marginBottom: 10 }}>Deep model class scores</h3>
                    <RankedBars
                      data={Object.entries(detection.deep_output.class_scores ?? {}).map(([name, score]) => ({ label: humanize(name), value: Number(Number(score).toFixed(4)) }))}
                      format={(value) => percent(value, 2)}
                    />
                  </div>
                )}
              </div>
            ) : (
              <EmptyState title="No class scores" detail="Per-class probabilities are retained with inference evidence." icon={<Icon name="activity" />} />
            )
          )}

          {tab === "evidence" && (
            <div className="grid-2">
              <div>
                <h3 style={{ fontSize: 12.5, marginBottom: 10 }}>Request identity</h3>
                <dl className="kv-list">
                  <KV k="Source address" v={<span className="mono">{active.sourceIp ?? "not recorded"}</span>} />
                  <KV k="Request id" v={<span className="mono">{active.requestId ?? "—"}</span>} />
                  <KV k="Event id" v={<span className="mono">{active.eventId}</span>} />
                  <KV k="Method and path" v={<span className="mono">{active.method} {active.path}</span>} />
                  <KV k="Query" v={<span className="mono">{active.query || "—"}</span>} />
                  <KV k="User agent" v={<span className="mono">{active.userAgent ?? "—"}</span>} />
                  <KV k="Upstream" v={<span className="mono">{active.upstream ?? "not reached"}</span>} />
                  <KV k="Occurred" v={formatDateTime(active.occurredAt)} />
                  <KV k="Journal category" v={humanize(active.category)} />
                </dl>
              </div>
              <div>
                <h3 style={{ fontSize: 12.5, marginBottom: 10 }}>Contributing context</h3>
                <ContextList details={parseJson(active.detailsJson)} />
              </div>
            </div>
          )}

          {tab === "raw" && <pre className="code-block">{JSON.stringify(parseJson(active.detailsJson), null, 2)}</pre>}
        </div>
      </section>

      <Panel title="Pick another request" subtitle="Selecting a row replays its journey above" flush>
        <EventTable events={snapshot.events.slice(0, 60)} selected={active} onSelect={select} highlight={liveIds} compact />
      </Panel>
    </div>
  );
}

function StageCard({ title, verdict, model, metrics }: { title: string; verdict: string; model?: string; metrics: [string, string][] }) {
  return (
    <article className="stage-card">
      <header>
        <span className="dot" style={{ background: colorFor(title) }} />
        <h3>{title}</h3>
      </header>
      <strong style={{ fontSize: 14, fontWeight: 600 }}>{verdict}</strong>
      <div className="stage-metrics">
        {metrics.map(([name, value]) => (
          <div key={name}>
            <small>{name}</small>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      {model && <p className="mono faint" style={{ fontSize: 10.5 }}>{model}</p>}
    </article>
  );
}

function ContextList({ details }: { details: Record<string, unknown> }) {
  const behaviour = details.behaviour as Record<string, unknown> | undefined;
  const network = details.network as Record<string, unknown> | undefined;
  const detection = details.detection as Record<string, unknown> | undefined;
  const explanation = (detection?.explanation_evidence ?? {}) as Record<string, string>;

  return (
    <dl className="kv-list">
      {behaviour && Object.entries(behaviour).map(([key, value]) => (
        <KV key={`b-${key}`} k={`Behaviour · ${humanize(key)}`} v={String(value)} />
      ))}
      {network && Object.entries(network).map(([key, value]) => (
        <KV key={`n-${key}`} k={`Network · ${humanize(key)}`} v={value === null ? "—" : String(value)} />
      ))}
      {Object.entries(explanation).map(([key, value]) => (
        <KV key={`e-${key}`} k={humanize(key)} v={<span className="mono">{value}</span>} />
      ))}
      {!behaviour && !network && !Object.keys(explanation).length && (
        <KV k="Context" v={<span className="muted">No behavioural or network context was retained</span>} />
      )}
    </dl>
  );
}
