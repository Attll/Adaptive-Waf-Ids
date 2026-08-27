import { useEffect, useMemo, useState } from "react";
import { recentNetworkEvidence, type NetworkEvidence } from "../api";
import { AreaChart, DonutChart, RankedBars, ScatterChart } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel } from "../components/Ui";
import { colorFor, formatTime, label as humanize, percent, relativeTime, shortId, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

export function NetworkPage({ snapshot, refreshInterval }: ViewProps) {
  const [state, setState] = useState<{ events: NetworkEvidence[]; model_version: string }>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      recentNetworkEvidence()
        .then((value) => !cancelled && (setState(value), setError(undefined)))
        .catch((reason) => !cancelled && setError(reason instanceof Error ? reason.message : "network sensor unavailable"));
    load();
    const timer = window.setInterval(load, Math.max(5, refreshInterval) * 1000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [refreshInterval]);

  const events = state?.events ?? [];
  const byClass = useMemo(
    () => events.reduce<Record<string, number>>((result, event) => {
      const name = event.network_class ?? "UNKNOWN";
      result[name] = (result[name] ?? 0) + 1;
      return result;
    }, {}),
    [events]
  );
  const bySource = useMemo(
    () => events.reduce<Record<string, number>>((result, event) => {
      result[event.source_ip] = (result[event.source_ip] ?? 0) + 1;
      return result;
    }, {}),
    [events]
  );
  const riskSeries = useMemo(() => [...events].reverse().map((event) => Number((event.network_risk * 100).toFixed(1))), [events]);
  const highest = events.length ? Math.max(...events.map((event) => event.network_risk)) : 0;
  const highRisk = events.filter((event) => event.network_risk >= snapshot.gatewayPolicy.blockRiskThreshold).length;

  if (error) {
    return (
      <div className="stack">
        <Panel title="Network sensor" action={<Badge value="UNAVAILABLE" tone="danger" />}>
          <EmptyState
            title="Network sensor unreachable"
            detail={`${error}. HTTP protection continues without network risk context, and the fused risk simply omits the network term.`}
            icon={<Icon name="network" />}
          />
        </Panel>
        <Panel title="What this affects">
          <dl className="kv-list">
            <KV k="HTTP detection" v={<Badge value="UNAFFECTED" tone="success" />} />
            <KV k="Network risk in fusion" v={<Badge value="OMITTED" tone="warning" />} />
            <KV k="Sensor health" v={<Badge value={snapshot.sensorHealth.status} />} />
          </dl>
        </Panel>
      </div>
    );
  }

  if (!state) {
    return <EmptyState title="Reading flow evidence" detail="Loading the sensor's current in-memory window." icon={<Icon name="network" />} />;
  }

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Flows in window" value={events.length} detail="Current sensor process window" tone="info" icon={<Icon name="network" size={13} />} spark={riskSeries} />
        <Metric label="High-risk sources" value={highRisk} detail={`At or above ${percent(snapshot.gatewayPolicy.blockRiskThreshold, 0)}`} tone="danger" icon={<Icon name="alert" size={13} />} />
        <Metric label="Peak network risk" value={percent(highest, 1)} detail="Across retained flow evidence" tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Serving model" value={shortId(state.model_version, 22)} detail={`Redis ${snapshot.sensorHealth.redis ?? "unknown"}`} tone="success" icon={<Icon name="models" size={13} />} />
      </div>

      <Panel title="Network risk over the retained flows" subtitle="Newest sample on the right">
        <AreaChart
          labels={[...events].reverse().map((event) => formatTime(event.observed_at).slice(0, 5))}
          height={190}
          yFormat={(value) => `${value}%`}
          series={[{ name: "Network risk", color: "#22d3ee", values: riskSeries }]}
        />
      </Panel>

      <div className="grid-2">
        <Panel title="Flow classification" subtitle="Classes assigned by the offline flow detector">
          <DonutChart data={sortedEntries(byClass).map(([name, value]) => ({ label: humanize(name), value }))} centerLabel="flows" size={144} />
        </Panel>
        <Panel title="Busiest source addresses">
          <RankedBars data={sortedEntries(bySource).slice(0, 8).map(([name, value]) => ({ label: name, value }))} />
        </Panel>
      </div>

      <Panel title="Risk against classifier confidence" subtitle="Each point is one classified flow">
        <ScatterChart
          height={220}
          xLabel="Confidence (%)"
          yLabel="Network risk"
          points={events
            .filter((event) => event.confidence !== undefined)
            .map((event) => ({
              x: (event.confidence ?? 0) * 100,
              y: event.network_risk,
              label: `${event.source_ip} · ${humanize(event.network_class ?? "UNKNOWN")}`,
              color: colorFor(event.network_class ?? "UNKNOWN")
            }))}
        />
      </Panel>

      <Panel title="Recent network classifications" flush>
        {events.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Observed</th><th>Source</th><th>Destination</th><th>Classification</th><th>Risk</th><th>Confidence</th></tr></thead>
              <tbody>
                {events.map((event) => (
                  <tr key={`${event.source_ip}-${event.observed_at}`}>
                    <td className="mono">{formatTime(event.observed_at)}<span className="cell-sub">{relativeTime(event.observed_at)}</span></td>
                    <td className="mono cell-strong">{event.source_ip}</td>
                    <td className="mono muted">{event.destination_ip ?? "—"}</td>
                    <td>
                      <span className="chip">
                        <i className="dot" style={{ background: colorFor(event.network_class ?? "UNKNOWN") }} />
                        {humanize(event.network_class ?? "UNKNOWN")}
                      </span>
                    </td>
                    <td>
                      <Badge
                        value={percent(event.network_risk, 1)}
                        tone={event.network_risk >= 0.81 ? "danger" : event.network_risk >= 0.5 ? "warning" : "success"}
                      />
                    </td>
                    <td className="mono muted">{event.confidence === undefined ? "—" : percent(event.confidence, 2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No flows submitted" detail="Replay captured flows into the sensor to populate this view." icon={<Icon name="network" />} />
        )}
      </Panel>
    </div>
  );
}
