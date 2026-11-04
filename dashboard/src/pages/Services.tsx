import type { DashboardSnapshot } from "../api";
import { RadialGauge, RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel } from "../components/Ui";
import { label as humanize, milliseconds, percent } from "../lib/format";
import type { ViewProps } from "../lib/view";

type ServiceRow = {
  name: string;
  status: string;
  detail: string;
  endpoint: string;
  responsibility: string;
};

const reportedModelCount = (snapshot: DashboardSnapshot) =>
  ["triage","router","injection","execution","deep","network"].filter((key)=>snapshot.runtimeModels.models[key]!==undefined).length;

export function Services({ snapshot, stream, refreshInterval }: ViewProps) {
  const rows = serviceRows(snapshot);
  const healthy = rows.filter((row) => row.status === "UP").length;
  const summary = snapshot.statistics.summary;

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Services ready" value={`${healthy}/${rows.length}`} detail={healthy === rows.length ? "All connected services are healthy" : "One or more dependencies are degraded"} tone={healthy === rows.length ? "success" : "danger"} icon={<Icon name="health" size={13} />} />
        <Metric label="Live stream" value={humanize(stream.state)} detail={`${stream.received} events pushed this session`} tone={stream.state === "live" ? "success" : "warning"} icon={<Icon name="live" size={13} />} />
        <Metric label="Poll interval" value={refreshInterval ? `${refreshInterval}s` : "Off"} detail="Full snapshot refresh cadence" tone="info" icon={<Icon name="refresh" size={13} />} />
        <Metric label="Gateway p95" value={milliseconds(summary.latencyP95Ms, 1)} detail={`mean inference ${milliseconds(summary.detectionLatencyMeanMs, 2)}`} tone="violet" icon={<Icon name="clock" size={13} />} />
      </div>

      <div className="grid-2">
        {rows.map((row) => (
          <article className="stage-card" key={row.name}>
            <header>
              <span className={`dot ${row.status === "UP" ? "success" : "danger"}${row.status === "UP" ? " live" : ""}`} />
              <h3>{row.name}</h3>
              <span style={{ marginLeft: "auto" }}><Badge value={row.status} /></span>
            </header>
            <p>{row.responsibility}</p>
            <dl className="kv-list">
              <KV k="State" v={row.detail} />
              <KV k="Probe" v={<span className="mono faint" style={{ fontSize: 10.5 }}>{row.endpoint}</span>} />
            </dl>
          </article>
        ))}
      </div>

      <div className="grid-2">
        <Panel title="Control-plane dependencies" subtitle="Reported by the control service actuator">
          <HealthComponents health={snapshot.controlHealth} />
        </Panel>
        <Panel title="Pipeline retained counts" subtitle="Retained window">
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
            <RadialGauge value={summary.total ? summary.detections / summary.total : 0} label="detected" color="#f5a524" />
            <RadialGauge value={summary.total ? summary.deepEscalations / summary.total : 0} label="escalated" color="#a855f7" />
          </div>
          <dl className="kv-list">
            <KV k="Requests retained" v={String(summary.total)} />
            <KV k="Deep escalations" v={`${summary.deepEscalations} (${percent(summary.total ? summary.deepEscalations / summary.total : 0, 1)})`} />
            <KV k="Mean upstream latency" v={milliseconds(summary.upstreamLatencyMeanMs, 2)} />
            <KV k="Reported model versions" v={String(reportedModelCount(snapshot))} />
          </dl>
        </Panel>
      </div>

      <Panel title="Latency budget" subtitle="Where end-to-end time is spent on average">
        <RankedBars
          data={[
            { label: "Model inference", value: Number(summary.detectionLatencyMeanMs.toFixed(3)) },
            { label: "Upstream application", value: Number(summary.upstreamLatencyMeanMs.toFixed(3)) },
            {
              label: "Gateway overhead",
              value: Number(Math.max(0, summary.latencyP50Ms - summary.detectionLatencyMeanMs - summary.upstreamLatencyMeanMs).toFixed(3))
            }
          ]}
          format={(value) => `${value.toFixed(2)} ms`}
        />
      </Panel>
    </div>
  );
}

function HealthComponents({ health }: { health: { status: string; components?: Record<string, { status: string }> } }) {
  const components = Object.entries(health.components ?? {});
  if (!components.length) {
    return (
      <EmptyState
        title="Aggregate readiness only"
        detail="The control actuator exposes overall health without dependency-level detail under its current policy."
        icon={<Icon name="health" />}
      />
    );
  }
  return (
    <dl className="kv-list">
      {components.map(([name, component]) => (
        <KV key={name} k={humanize(name)} v={<Badge value={component.status} />} />
      ))}
    </dl>
  );
}

function healthStatus(health: { status: string }) {
  return ["UP", "OK", "READY"].includes((health.status ?? "").toUpperCase()) ? "UP" : (health.status ?? "UNKNOWN").toUpperCase();
}

function serviceRows(snapshot: DashboardSnapshot): ServiceRow[] {
  return [
    {
      name: "Gateway",
      status: healthStatus(snapshot.gatewayHealth),
      detail: `${humanize(snapshot.mode.mode)} mode · policy v${snapshot.gatewayPolicy.version}`,
      endpoint: "GET /gateway-api/actuator/health",
      responsibility: "Terminates traffic, calls detection, applies policy, and journals every decision."
    },
    {
      name: "Detection",
      status: healthStatus(snapshot.detectionReady),
      detail: `${reportedModelCount(snapshot)} model versions reported`,
      endpoint: "GET /detection-api/ready",
      responsibility: "Runs the adaptive hierarchy: triage, router, fast experts, and deep escalation."
    },
    {
      name: "Control plane",
      status: healthStatus(snapshot.controlHealth),
      detail: `${snapshot.events.length} events retained · ${snapshot.audit.length} audit entries`,
      endpoint: "GET /control-api/actuator/health",
      responsibility: "Owns policy, the model registry, the event journal, reviews, and the audit log."
    },
    {
      name: "Network sensor",
      status: healthStatus(snapshot.sensorHealth),
      detail: `Redis ${snapshot.sensorHealth.redis ?? "unknown"} · ${snapshot.sensorHealth.model_version ?? "model unavailable"}`,
      endpoint: "GET /sensor-api/health",
      responsibility: "Classifies network flows and publishes risk context the gateway reads per request."
    },
    {
      name: "Adaptation",
      status: healthStatus(snapshot.adaptationHealth),
      detail: `${snapshot.trainingRuns.length} training runs registered`,
      endpoint: "GET /adaptation-api/health",
      responsibility: "Curates operator feedback, measures drift, and registers candidate models."
    }
  ];
}
