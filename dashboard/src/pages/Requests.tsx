import { useMemo, useState } from "react";
import type { EventRecord } from "../api";
import { AreaChart, DonutChart, RankedBars } from "../components/Charts";
import { EventTable } from "../components/EventTable";
import { Icon, Metric, Panel, Segmented } from "../components/Ui";
import { formatTime, isDetection, label as humanize, milliseconds, percent, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

type Scope = "all" | "detections" | "blocked" | "allowed";

export function Requests(props: ViewProps) {
  const { snapshot, selected, select, goTo, liveIds } = props;
  const [scope, setScope] = useState<Scope>("all");
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<"time" | "risk" | "latency">("time");

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const scoped = snapshot.events.filter((event) => {
      if (scope === "detections") return isDetection(event);
      if (scope === "blocked") return event.action === "BLOCK" || event.action === "RATE_LIMIT" || event.action === "TEMPORARY_BLOCK";
      if (scope === "allowed") return event.action === "ALLOW";
      return true;
    });
    const matched = needle
      ? scoped.filter((event) =>
          [event.path, event.query, event.method, event.predictedAttack, event.action, event.sourceIp, event.mitigation, event.requestId, event.routingPath]
            .filter(Boolean)
            .join(" ")
            .toLowerCase()
            .includes(needle)
        )
      : scoped;
    return [...matched].sort((first, second) => {
      if (sort === "risk") return second.risk - first.risk;
      if (sort === "latency") return second.gatewayLatencyMs - first.gatewayLatencyMs;
      return new Date(second.occurredAt).getTime() - new Date(first.occurredAt).getTime();
    });
  }, [snapshot.events, scope, filter, sort]);

  const stats = useMemo(() => summarize(filtered), [filtered]);
  const timeline = snapshot.statistics.timeline;

  return (
    <div className="stack">
      <div className="toolbar">
        <div className="search-bar">
          <Icon name="search" size={14} />
          <input
            placeholder="Filter by path, query, source address, classification, mitigation, or route"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </div>
        <Segmented<Scope>
          value={scope}
          onChange={setScope}
          options={[
            { value: "all", label: "All" },
            { value: "detections", label: "Detections" },
            { value: "blocked", label: "Mitigated" },
            { value: "allowed", label: "Allowed" }
          ]}
        />
        <Segmented<"time" | "risk" | "latency">
          value={sort}
          onChange={setSort}
          options={[
            { value: "time", label: "Newest" },
            { value: "risk", label: "Risk" },
            { value: "latency", label: "Slowest" }
          ]}
        />
        <span className="toolbar-count">{filtered.length} of {snapshot.events.length}</span>
      </div>

      <div className="grid-4 stagger">
        <Metric label="In view" value={filtered.length} detail={`${stats.detections} classified as attacks`} tone="info" icon={<Icon name="requests" size={13} />} />
        <Metric label="Mitigated" value={stats.mitigated} detail={`${percent(filtered.length ? stats.mitigated / filtered.length : 0, 1)} of the current view`} tone="danger" icon={<Icon name="shield" size={13} />} />
        <Metric label="Mean risk" value={percent(stats.meanRisk, 1)} detail={`peak ${percent(stats.maxRisk, 1)}`} tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Mean latency" value={milliseconds(stats.meanLatency, 1)} detail={`inference ${milliseconds(stats.meanInference, 2)}`} tone="violet" icon={<Icon name="clock" size={13} />} />
      </div>

      <div className="grid-2">
        <Panel title="Volume over time" subtitle="Retained window, one bucket per minute">
          <AreaChart
            labels={timeline.map((point) => formatTime(point.bucket).slice(0, 5))}
            height={170}
            series={[
              { name: "Requests", color: "#3b82f6", values: timeline.map((point) => point.total) },
              { name: "Detections", color: "#f5a524", values: timeline.map((point) => point.detections) }
            ]}
          />
        </Panel>
        <Panel title="Classification split" subtitle="Across the filtered view">
          <DonutChart
            data={sortedEntries(stats.byAttack).map(([name, value]) => ({ label: humanize(name), value }))}
            centerLabel="requests"
            size={140}
          />
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Busiest endpoints">
          <RankedBars data={sortedEntries(stats.byEndpoint).slice(0, 8).map(([name, value]) => ({ label: name, value }))} />
        </Panel>
        <Panel title="Slowest endpoints" subtitle="Mean gateway latency">
          <RankedBars
            data={stats.slowest.map((entry) => ({ label: entry.endpoint, value: Number(entry.mean.toFixed(2)) }))}
            format={(value) => `${value.toFixed(2)} ms`}
            colorKey={() => "#a855f7"}
          />
        </Panel>
      </div>

      <Panel
        title="Request decision log"
        subtitle="Every request the control plane retained, with its source, decision, and timing"
        action={selected && <button className="link-btn" onClick={() => goTo("Request Visualizer")}>Inspect selected</button>}
        flush
      >
        <EventTable events={filtered} selected={selected} onSelect={select} highlight={liveIds} />
      </Panel>
    </div>
  );
}

function summarize(events: EventRecord[]) {
  const byAttack: Record<string, number> = {};
  const byEndpoint: Record<string, number> = {};
  const latencyByEndpoint = new Map<string, number[]>();
  let riskTotal = 0;
  let maxRisk = 0;
  let latencyTotal = 0;
  let latencyCount = 0;
  let inferenceTotal = 0;
  let inferenceCount = 0;
  let detections = 0;
  let mitigated = 0;

  events.forEach((event) => {
    const attack = event.predictedAttack ?? "UNKNOWN";
    byAttack[attack] = (byAttack[attack] ?? 0) + 1;
    const endpoint = `${event.method ?? "?"} ${event.path ?? "/"}`;
    byEndpoint[endpoint] = (byEndpoint[endpoint] ?? 0) + 1;
    riskTotal += event.risk;
    maxRisk = Math.max(maxRisk, event.risk);
    if (event.gatewayLatencyMs > 0) {
      latencyTotal += event.gatewayLatencyMs;
      latencyCount += 1;
      latencyByEndpoint.set(endpoint, [...(latencyByEndpoint.get(endpoint) ?? []), event.gatewayLatencyMs]);
    }
    if (event.detectionLatencyMs > 0) {
      inferenceTotal += event.detectionLatencyMs;
      inferenceCount += 1;
    }
    if (isDetection(event)) detections += 1;
    if (["BLOCK", "RATE_LIMIT", "TEMPORARY_BLOCK"].includes(event.action ?? "")) mitigated += 1;
  });

  const slowest = [...latencyByEndpoint.entries()]
    .map(([endpoint, values]) => ({ endpoint, mean: values.reduce((sum, value) => sum + value, 0) / values.length }))
    .sort((first, second) => second.mean - first.mean)
    .slice(0, 8);

  return {
    byAttack,
    byEndpoint,
    slowest,
    detections,
    mitigated,
    meanRisk: events.length ? riskTotal / events.length : 0,
    maxRisk,
    meanLatency: latencyCount ? latencyTotal / latencyCount : 0,
    meanInference: inferenceCount ? inferenceTotal / inferenceCount : 0
  };
}
