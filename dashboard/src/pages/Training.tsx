import { useMemo,useEffect,useState } from "react";
import type { TrainingRun } from "../api";
import { GroupedBarChart, RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, Metric, Panel } from "../components/Ui";
import { colorFor, formatDateTime, label as humanize, parseJson, shortId } from "../lib/format";
import type { ViewProps } from "../lib/view";

export function Training({ snapshot,runs:consoleRuns,api,goTo }: ViewProps) {
  const [routingRuns,setRoutingRuns]=useState<Awaited<ReturnType<typeof api.routingRuns>>['runs']>([]);
  const [routingError,setRoutingError]=useState('');
  useEffect(()=>{let active=true;void api.routingRuns().then(result=>{if(active){setRoutingRuns(result.runs);setRoutingError('');}}).catch(error=>{if(active)setRoutingError(String(error));});return()=>{active=false;};},[api,consoleRuns]);
  const runs = snapshot.trainingRuns;

  const comparison = useMemo(() => {
    const scored = runs
      .map((run) => ({ run, metrics: parseJson(run.metricsJson) as Record<string, number> }))
      .filter((entry) => Object.keys(entry.metrics).length)
      .slice(0, 8)
      .reverse();
    const metricNames = [...new Set(scored.flatMap((entry) => Object.keys(entry.metrics)))]
      .filter((name) => /accuracy|precision|recall|f1|auc|fpr|coverage/.test(name) && scored.some((entry) => typeof entry.metrics[name] === "number"))
      .slice(0, 4);
    return {
      groups: scored.map((entry) => entry.run.modelName),
      series: metricNames.map((name, index) => ({
        name: humanize(name),
        color: colorFor(name, index + 2),
        values: scored.map((entry) => Number(entry.metrics[name] ?? 0))
      }))
    };
  }, [runs]);

  const completed = runs.filter((run) => run.completedAt).length;
  const shadow = runs.filter((run) => run.shadowMode).length;

  return (
    <div className="stack">
      <Panel title="Saved routing experiments" subtitle="Persistent offline policy training; no automatic deployment"><button className="btn" onClick={()=>goTo('RL Training')}>Open RL Training</button>{routingError&&<p>{routingError}</p>}<div className="table-wrap"><table><thead><tr><th>Run ID</th><th>Population</th><th>Elapsed seconds</th></tr></thead><tbody>{routingRuns.map(run=><tr key={run.run_id}><td>{run.run_id}</td><td>{run.data_origin}</td><td>{run.elapsed_seconds.toFixed(3)}</td></tr>)}</tbody></table></div></Panel>
      {consoleRuns.some(run=>run.kind==='RL Training')&&<Panel title="Offline routing training runs" subtitle="Shared with RL Training; these fitted policies remain shadow-only"><div className="table-wrap"><table><thead><tr><th>Run ID</th><th>Policies</th><th>Summary</th></tr></thead><tbody>{consoleRuns.filter(run=>run.kind==='RL Training').map(run=><tr key={run.id}><td className="mono">{run.id}</td><td>{run.count}</td><td><pre>{JSON.stringify(run.summary)}</pre></td></tr>)}</tbody></table></div></Panel>}
      <div className="grid-4 stagger">
        <Metric label="Registered runs" value={runs.length} detail={`${completed} completed`} tone="info" icon={<Icon name="training" size={13} />} />
        <Metric label="Shadow evaluations" value={shadow} detail="Evaluated without serving traffic" tone="violet" icon={<Icon name="layers" size={13} />} />
        <Metric label="Challengers" value={runs.filter((run) => run.status === "CHALLENGER").length} detail="Awaiting an operator decision" tone="warning" icon={<Icon name="target" size={13} />} />
        <Metric label="Promotion policy" value="Operator gated" detail="Candidate review, runtime acknowledgement and measured gates are required" tone="success" icon={<Icon name="shield" size={13} />} />
      </div>

      {comparison.groups.length > 0 && (
        <Panel title="Candidate metrics across runs" subtitle="Metrics reported by the adaptation service for each registered candidate">
          <GroupedBarChart groups={comparison.groups} series={comparison.series} height={240} domainMax={1} format={(value) => `${(value * 100).toFixed(0)}%`} />
        </Panel>
      )}

      <Panel title="Controlled training lifecycle" subtitle="Every run recorded by the adaptation workflow" flush>
        {runs.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Run</th><th>Candidate</th><th>Dataset</th><th>Status</th><th>Metrics</th><th>Drift</th><th>Duration</th></tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.externalRunId}>
                    <td>
                      <span className="cell-strong mono">{shortId(run.externalRunId, 18)}</span>
                      <span className="cell-sub">{formatDateTime(run.startedAt)}</span>
                    </td>
                    <td>
                      <span className="cell-strong">{run.modelName}</span>
                      <span className="cell-sub">{run.shadowMode ? "Shadow evaluation" : "Managed training"}</span>
                    </td>
                    <td className="mono muted">{run.datasetVersion}</td>
                    <td><Badge value={run.status} /></td>
                    <td><MetricChips json={run.metricsJson} /></td>
                    <td><DriftSummary run={run} /></td>
                    <td className="mono muted">{duration(run)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No training runs registered" detail="Runs appear after the adaptation service registers a candidate with the control plane." icon={<Icon name="training" />} />
        )}
      </Panel>

      <Panel title="Curated feedback signal" subtitle="Operator verdicts that will seed the next curation run">
        <RankedBars
          data={Object.entries(
            snapshot.feedback.reduce<Record<string, number>>((result, item) => {
              result[item.verdict] = (result[item.verdict] ?? 0) + 1;
              return result;
            }, {})
          ).map(([name, value]) => ({ label: humanize(name), value }))}
        />
      </Panel>
    </div>
  );
}

function MetricChips({ json }: { json?: string }) {
  const metrics = parseJson(json);
  const entries = Object.entries(metrics).filter(([, value]) => typeof value === "number" || typeof value === "string");
  if (!entries.length) return <span className="muted">No metrics recorded</span>;
  return (
    <div className="chip-row">
      {entries.slice(0, 4).map(([name, value]) => (
        <span className="chip" key={name}>
          {humanize(name)} <strong>{typeof value === "number" ? formatNumber(name, value) : String(value)}</strong>
        </span>
      ))}
    </div>
  );
}

function DriftSummary({ run }: { run: TrainingRun }) {
  const drift = parseJson(run.driftJson);
  if (typeof drift.reason === "string") return <span style={{ color: "var(--danger)", fontSize: 11.5 }}>{drift.reason}</span>;
  const entries = Object.entries(drift);
  if (!entries.length) return <span className="muted">No drift flagged</span>;
  return (
    <div className="chip-row">
      {entries.slice(0, 2).map(([name, value]) => (
        <span className="chip" key={name}>{humanize(name)} <strong>{String(value)}</strong></span>
      ))}
    </div>
  );
}

function formatNumber(name: string, value: number): string {
  const key = name.toLowerCase();
  if (key.includes("ms") || key.includes("latency")) return `${value.toFixed(2)} ms`;
  if (["f1", "recall", "accuracy", "precision", "auc", "coverage"].some((token) => key.includes(token))) return `${(value * 100).toFixed(1)}%`;
  return value.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
}

function duration(run: TrainingRun): string {
  if (!run.completedAt) return "running";
  const delta = new Date(run.completedAt).getTime() - new Date(run.startedAt).getTime();
  if (delta < 1000) return `${delta} ms`;
  if (delta < 60_000) return `${(delta / 1000).toFixed(1)} s`;
  return `${(delta / 60_000).toFixed(1)} min`;
}
