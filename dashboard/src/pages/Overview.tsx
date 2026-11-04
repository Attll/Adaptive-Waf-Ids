import { useMemo } from "react";
import type { EventRecord } from "../api";
import { AreaChart, DonutChart, RadialGauge, RankedBars, ScatterChart } from "../components/Charts";
import { EventTable } from "../components/EventTable";
import { Badge, Icon, KV, Metric, Panel, EmptyState } from "../components/Ui";
import {
  colorFor,
  formatTime,
  label as humanize,
  milliseconds,
  percent,
  relativeTime,
  sortedEntries
} from "../lib/format";
import type { ViewProps } from "../lib/view";

export function Overview(props: ViewProps) {
  const { snapshot, goTo, select, liveIds } = props;
  const { events, statistics } = snapshot;
  const summary = statistics.summary;

  const timeline = statistics.timeline;
  const timelineLabels = timeline.map((point) => formatTime(point.bucket).slice(0, 5));
  const blockRate = summary.total ? summary.blocked / summary.total : 0;
  const detectionRate = summary.total ? summary.detections / summary.total : 0;

  const attackData = useMemo(
    () => sortedEntries(statistics.byAttack).map(([name, value]) => ({ label: humanize(name), value })),
    [statistics.byAttack]
  );
  const endpointData = useMemo(
    () => sortedEntries(statistics.byEndpoint).slice(0, 8).map(([name, value]) => ({ label: name, value })),
    [statistics.byEndpoint]
  );
  const routeData = useMemo(
    () => sortedEntries(statistics.byRoute).slice(0, 6).map(([name, value]) => ({ label: compactRoute(name), value })),
    [statistics.byRoute]
  );
  const modelUsage = useMemo(() => modelUsageBreakdown(events), [events]);
  const scatter = useMemo(
    () =>
      events
        .filter((event) => event.gatewayLatencyMs > 0)
        .slice(0, 220)
        .map((event) => ({
          x: event.gatewayLatencyMs,
          y: event.risk,
          label: `${event.method ?? "?"} ${event.path ?? "/"}`,
          color: colorFor(event.predictedAttack ?? "UNKNOWN")
        })),
    [events]
  );

  return (
    <div className="stack">
      {props.runs.length>0&&<Panel title="Recent console runs" subtitle="Shared across Generator, Model Lab and Timing; gateway totals below come from the persisted journal"><div className="table-wrap"><table><thead><tr><th>Run</th><th>Requests</th><th>Outcome</th></tr></thead><tbody>{props.runs.slice(0,5).map(run=><tr key={run.id}><td>{run.kind}{run.stop&&run.summary?.state==='running'&&<button className="btn danger" onClick={run.stop}>Stop run</button>}</td><td>{run.count}</td><td>{run.kind==='Timing'?`${Number(run.summary?.p95Ms??0).toFixed(1)} ms p95 · ${Number(run.summary?.httpResponsesPerSecond??0).toFixed(1)} responses/s · ${run.summary?.errors??0} errors`:run.kind==='RL Training'?'Six shadow policies trained':run.kind==='Model Lab'?'Model-only outputs available':run.kind==='Network Generator'?`${run.summary?.classified??0} flows classified`:`${String(run.summary?.state??'running')} · ${run.summary?.journalled??0} journalled`}</td></tr>)}</tbody></table></div></Panel>}
      <div className="grid-4 stagger">
        <Metric
          label="Requests observed"
          value={summary.allTimeTotal??summary.total}
          detail={`${summary.total} recent requests · ${summary.fullyInspected ?? 0} fully inspected in that window`}
          tone="info"
          icon={<Icon name="requests" size={13} />}
          spark={timeline.map((point) => point.total)}
        />
        <Metric
          label="Recent detections"
          value={summary.detections}
          detail={`${percent(detectionRate, 1)} of observed traffic`}
          tone="warning"
          icon={<Icon name="target" size={13} />}
          spark={timeline.map((point) => point.detections)}
        />
        <Metric
          label="Recent gateway blocks"
          value={summary.blocked}
          detail={`${summary.rateLimited} additionally rate limited`}
          tone="danger"
          icon={<Icon name="shield" size={13} />}
          spark={timeline.map((point) => point.blocked)}
        />
        <Metric
          label="End-to-end p95"
          value={milliseconds(summary.latencyP95Ms, 1)}
          detail={`p50 ${milliseconds(summary.latencyP50Ms, 1)} · p99 ${milliseconds(summary.latencyP99Ms, 1)}`}
          tone="violet"
          icon={<Icon name="clock" size={13} />}
        />
      </div>

      <Panel
        title="Traffic and enforcement timeline"
        subtitle="One bucket per minute across the retained window"
        action={<button className="link-btn" onClick={() => goTo("Requests")}>Open request log</button>}
      >
        <AreaChart
          labels={timelineLabels}
          height={220}
          series={[
            { name: "Requests", color: "#3b82f6", values: timeline.map((point) => point.total) },
            { name: "Detections", color: "#f5a524", values: timeline.map((point) => point.detections) },
            { name: "Blocked", color: "#ff5c5c", values: timeline.map((point) => point.blocked) }
          ]}
        />
      </Panel>

      <div className="grid-2">
        <Panel title="Attack classification" subtitle="Every class the pipeline assigned in this window">
          <DonutChart data={attackData} centerLabel="requests" />
        </Panel>
        <Panel title="Endpoints targeted" subtitle="Ranked by request volume">
          <RankedBars data={endpointData} />
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Models exercised" subtitle="Which stages actually ran, counted per request">
          {modelUsage.length ? <RankedBars data={modelUsage} colorKey={(name) => colorFor(name)} /> : (
            <EmptyState title="No stage evidence yet" detail="Model usage appears once the gateway records detection evidence with an event." icon={<Icon name="models" />} />
          )}
        </Panel>
        <Panel title="Adaptive routes taken" subtitle="Distinct paths through the pipeline">
          {routeData.length ? <RankedBars data={routeData} /> : (
            <EmptyState title="No routes recorded" detail="Routes appear once inference evidence is retained with a request." icon={<Icon name="flow" />} />
          )}
        </Panel>
      </div>

      <Panel title="Source address map" subtitle="Origins ranked by volume, with what each one attempted">
        {statistics.sources.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Requests</th>
                  <th>Detections</th>
                  <th>Blocked</th>
                  <th>Peak risk</th>
                  <th>Mean latency</th>
                  <th>Attempted</th>
                  <th>Endpoints</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {statistics.sources.map((source) => (
                  <tr key={source.sourceIp}>
                    <td className="mono cell-strong">{source.sourceIp}</td>
                    <td className="tabular">{source.requests}</td>
                    <td className="tabular">{source.detections}</td>
                    <td className="tabular">{source.blocked}</td>
                    <td>
                      <Badge
                        value={`${(source.maxRisk * 100).toFixed(0)}%`}
                        tone={source.maxRisk >= 0.81 ? "danger" : source.maxRisk >= 0.5 ? "warning" : "success"}
                      />
                    </td>
                    <td className="mono muted">{milliseconds(source.meanLatencyMs, 1)}</td>
                    <td>
                      <div className="chip-row">
                        {Object.entries(source.attacks).slice(0, 3).map(([attack, count]) => (
                          <span className="chip" key={attack}>
                            <i className="dot" style={{ background: colorFor(attack) }} />
                            {humanize(attack)} <strong>{count}</strong>
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono muted">{Object.keys(source.endpoints).slice(0, 2).join(", ") || "—"}</td>
                    <td className="muted">{source.lastSeen ? relativeTime(source.lastSeen) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No source addresses recorded" detail="Origins appear as soon as the gateway journals a request." icon={<Icon name="globe" />} />
        )}
      </Panel>

      <div className="grid-2">
        <Panel title="Risk against end-to-end latency" subtitle="Each point is one journalled request">
          <ScatterChart points={scatter} xLabel="Gateway latency (ms)" yLabel="Overall risk" />
        </Panel>
        <Panel title="Posture" subtitle="Applied enforcement configuration">
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center", marginBottom: 6 }}>
            <RadialGauge value={blockRate} label="blocked" color="#ff5c5c" />
            <RadialGauge value={detectionRate} label="detected" color="#f5a524" />
            <RadialGauge value={snapshot.gatewayPolicy.blockRiskThreshold} label="threshold" color="#3b82f6" />
          </div>
          <dl className="kv-list">
            <KV k="Gateway mode" v={<Badge value={snapshot.mode.mode} />} />
            <KV k="Applied policy" v={`v${snapshot.gatewayPolicy.version}`} />
            <KV k="Short-window limit" v={`${snapshot.gatewayPolicy.rateLimitShortWindow} requests`} />
            <KV k="Deep escalations" v={String(summary.deepEscalations)} />
            <KV k="Mean inference" v={milliseconds(summary.detectionLatencyMeanMs, 2)} />
            <KV k="Mean upstream" v={milliseconds(summary.upstreamLatencyMeanMs, 2)} />
            <KV k="Protected applications" v={String(snapshot.applications.filter((app) => app.enabled).length)} />
          </dl>
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Mitigation outcome" subtitle="What the gateway did with each decision">
          <RankedBars
            data={sortedEntries(statistics.byMitigation).map(([name, value]) => ({ label: humanize(name), value }))}
            colorKey={(name) => (name.toLowerCase().includes("block") || name.toLowerCase().includes("rate") ? "#ff5c5c" : "#2bd576")}
          />
        </Panel>
        <Panel title="Response status" subtitle="HTTP status returned to the caller">
          <DonutChart
            data={sortedEntries(statistics.byStatus).map(([name, value]) => ({ label: name, value }))}
            centerLabel="responses"
          />
        </Panel>
      </div>

      <Panel
        title="Latest decisions"
        action={<button className="link-btn" onClick={() => goTo("Request Visualizer")}>Open visualizer</button>}
        flush
      >
        <EventTable
          events={events.slice(0, 10)}
          selected={props.selected}
          highlight={liveIds}
          onSelect={(event) => { select(event); goTo("Request Visualizer"); }}
        />
      </Panel>
    </div>
  );
}

/** Counts how often each pipeline stage participated, derived from the routing path recorded on the event. */
function modelUsageBreakdown(events: EventRecord[]): { label: string; value: number }[] {
  const counts = new Map<string, number>();
  events.forEach((event) => {
    (event.routingPath ?? "")
      .split(" > ")
      .map((step) => step.trim())
      .filter((step) => step && step !== "POLICY_PENDING")
      .forEach((step) => counts.set(step, (counts.get(step) ?? 0) + 1));
  });
  return [...counts.entries()]
    .sort(([, first], [, second]) => second - first)
    .map(([name, value]) => ({ label: humanize(name), value }));
}

function compactRoute(route: string): string {
  return route
    .split(" > ")
    .map((step) => humanize(step).replace(" Fast", "").replace("Policy Pending", "Policy"))
    .join(" → ");
}
