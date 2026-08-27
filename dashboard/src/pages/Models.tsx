import { useEffect, useMemo, useState } from "react";
import {
  detectBatch,
  modelCatalog,
  probeGateway,
  type BatchProbe,
  type BatchResponse,
  type CatalogStage,
  type DetectionEvidence,
  type GatewayProbeResult,
  type ModelCatalog
} from "../api";
import { ConfusionMatrix, DonutChart, GroupedBarChart, RankedBars, ScatterChart } from "../components/Charts";
import { buildFlow, RequestFlow } from "../components/RequestFlow";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Segmented, Switch, Tabs } from "../components/Ui";
import { bytes, colorFor, label as humanize, milliseconds, percent, scalar, sortedEntries } from "../lib/format";
import { PROBE_FAMILIES, PROBE_LIBRARY, type ViewProps } from "../lib/view";

type Tab = "pipeline" | "comparison" | "playground" | "batch" | "registry";

const COMPARABLE_METRICS = [
  { key: "accuracy", label: "Accuracy", kind: "ratio" as const },
  { key: "f1_macro", label: "F1 (macro)", kind: "ratio" as const },
  { key: "precision_macro", label: "Precision (macro)", kind: "ratio" as const },
  { key: "recall_macro", label: "Recall (macro)", kind: "ratio" as const },
  { key: "roc_auc", label: "ROC AUC", kind: "ratio" as const },
  { key: "pr_auc", label: "PR AUC", kind: "ratio" as const },
  { key: "inference_p50_ms", label: "Inference p50", kind: "ms" as const },
  { key: "inference_p95_ms", label: "Inference p95", kind: "ms" as const }
];

export function Models(props: ViewProps) {
  const [tab, setTab] = useState<Tab>("pipeline");
  const [catalog, setCatalog] = useState<ModelCatalog>();
  const [catalogError, setCatalogError] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    modelCatalog()
      .then((value) => !cancelled && setCatalog(value))
      .catch((error) => !cancelled && setCatalogError(error instanceof Error ? error.message : "catalog unavailable"));
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="stack">
      <section className="panel">
        <Tabs<Tab>
          value={tab}
          onChange={setTab}
          options={[
            { value: "pipeline", label: "Pipeline" },
            { value: "comparison", label: "Comparison" },
            { value: "playground", label: "Query models" },
            { value: "batch", label: "Batch probe" },
            { value: "registry", label: "Registry" }
          ]}
        />
        <div className="panel-body">
          {tab === "pipeline" && <PipelineTab catalog={catalog} error={catalogError} {...props} />}
          {tab === "comparison" && <ComparisonTab catalog={catalog} error={catalogError} />}
          {tab === "playground" && <PlaygroundTab />}
          {tab === "batch" && <BatchTab {...props} />}
          {tab === "registry" && <RegistryTab {...props} />}
        </div>
      </section>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Pipeline
 * ------------------------------------------------------------------ */
function PipelineTab({ catalog, error, snapshot }: { catalog?: ModelCatalog; error?: string } & ViewProps) {
  const [stageKey, setStageKey] = useState<string>();
  if (error) return <EmptyState title="Model catalog unavailable" detail={error} icon={<Icon name="models" />} />;
  if (!catalog) return <EmptyState title="Reading artifacts" detail="Loading the deployed pipeline and its evaluation record." icon={<Icon name="models" />} />;

  const stage = catalog.stages.find((entry) => entry.stage === stageKey) ?? catalog.stages[0];
  const deployed = stage.candidates.find((candidate) => candidate.deployed) ?? stage.candidates[0];

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Stages deployed" value={catalog.stages.length} detail={`calibration run ${catalog.pipeline.calibration_run ?? "—"}`} tone="info" icon={<Icon name="layers" size={13} />} />
        <Metric label="Runtime models loaded" value={Object.keys(catalog.runtime).length} detail="Reported by the detection service" tone="success" icon={<Icon name="models" size={13} />} />
        <Metric label="Escalation threshold" value={percent(Number(catalog.pipeline.thresholds.expert_minimum_confidence ?? 0), 0)} detail="Below this, the deep model adjudicates" tone="violet" icon={<Icon name="bolt" size={13} />} />
        <Metric label="Block threshold" value={percent(snapshot.gatewayPolicy.blockRiskThreshold, 0)} detail={`applied policy v${snapshot.gatewayPolicy.version}`} tone="danger" icon={<Icon name="shield" size={13} />} />
      </div>

      <div className="grid-3">
        {catalog.stages.map((entry) => {
          const best = entry.candidates.find((candidate) => candidate.deployed) ?? entry.candidates[0];
          return (
            <article
              key={entry.stage}
              className={`stage-card${entry.stage === stage.stage ? " selected" : ""}`}
              onClick={() => setStageKey(entry.stage)}
              style={{ cursor: "pointer" }}
            >
              <header>
                <span className="dot" style={{ background: colorFor(entry.stage) }} />
                <h3>{entry.title}</h3>
                <span style={{ marginLeft: "auto" }}><Badge value={entry.plane === "http" ? "HTTP" : "NETWORK"} tone="neutral" /></span>
              </header>
              <p>{entry.purpose}</p>
              <div className="chip-row">
                <span className="chip">{entry.deployment.profile.family}</span>
                <span className="chip">{humanize(entry.deployment.algorithm)}</span>
                {entry.deployment.calibration && <span className="chip">{humanize(entry.deployment.calibration)} calibrated</span>}
              </div>
              <div>
                <small className="faint" style={{ fontSize: 10, display: "block", marginBottom: 4 }}>Prevents</small>
                <div className="chip-row">
                  {entry.defends_against.map((attack) => (
                    <span className="chip" key={attack}>
                      <i className="dot" style={{ background: colorFor(attack) }} />
                      {humanize(attack)}
                    </span>
                  ))}
                </div>
              </div>
              <div className="stage-metrics">
                <div>
                  <small>{best?.metrics.accuracy !== undefined ? "Accuracy" : "Top-1"}</small>
                  <strong>{percent(best?.metrics.accuracy ?? best?.metrics.top1_accuracy ?? 0, 2)}</strong>
                </div>
                <div>
                  <small>F1 macro</small>
                  <strong>{best?.metrics.f1_macro !== undefined ? percent(best.metrics.f1_macro, 2) : "—"}</strong>
                </div>
                <div>
                  <small>p50 latency</small>
                  <strong>{milliseconds(best?.metrics.inference_p50_ms, 1)}</strong>
                </div>
              </div>
              <p className="mono faint" style={{ fontSize: 10.5 }}>{entry.deployment.model_version}</p>
            </article>
          );
        })}
      </div>

      <div className="grid-2">
        <Panel title={`${stage.title} — deployment`} subtitle={stage.purpose}>
          <dl className="kv-list">
            <KV k="Model family" v={stage.deployment.profile.family} />
            <KV k="Algorithm" v={humanize(stage.deployment.algorithm)} />
            <KV k="Training run" v={<span className="mono">{stage.deployment.run_id}</span>} />
            <KV k="Calibration" v={stage.deployment.calibration ? humanize(stage.deployment.calibration) : "None"} />
            <KV k="Dataset" v={<span className="mono">{stage.deployment.dataset_version ?? "—"}</span>} />
            <KV k="Feature version" v={<span className="mono">{stage.deployment.feature_version ?? "—"}</span>} />
            {stage.deployment.device && <KV k="Device" v={stage.deployment.device} />}
            {stage.deployment.router_thresholds?.minimum_top1_probability !== undefined && (
              <>
                <KV k="Router min top-1" v={percent(stage.deployment.router_thresholds.minimum_top1_probability, 0)} />
                <KV k="Router min margin" v={percent(stage.deployment.router_thresholds.minimum_top1_margin ?? 0, 0)} />
              </>
            )}
            <KV k="Serving version" v={<span className="mono">{catalog.runtime[stage.stage] ?? stage.deployment.model_version}</span>} />
            <KV k="Artifact" v={<span className="mono faint" style={{ fontSize: 10.5 }}>{stage.deployment.artifact || "—"}</span>} />
          </dl>
          <p className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>{stage.deployment.profile.description}</p>
        </Panel>

        <Panel title={`${stage.title} — hyperparameters`} subtitle="Exactly what this artifact was trained with">
          {Object.keys(stage.deployment.hyperparameters).length ? (
            <dl className="kv-list">
              {Object.entries(stage.deployment.hyperparameters).map(([name, value]) => (
                <KV key={name} k={humanize(name)} v={<span className="mono">{scalar(value)}</span>} />
              ))}
            </dl>
          ) : (
            <EmptyState title="No hyperparameters recorded" detail="This run's training config did not record parameters for the deployed algorithm." icon={<Icon name="settings" />} />
          )}
          <div style={{ marginTop: 14 }}>
            <small className="faint" style={{ fontSize: 10, display: "block", marginBottom: 6 }}>Attacks this stage prevents</small>
            <div className="chip-row">
              {stage.defends_against.map((attack) => (
                <span className="chip" key={attack}>
                  <i className="dot" style={{ background: colorFor(attack) }} />
                  {humanize(attack)}
                </span>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 14 }}>
            <small className="faint" style={{ fontSize: 10, display: "block", marginBottom: 6 }}>Classes it can output</small>
            <div className="chip-row">
              {stage.labels.map((name) => <span className="chip" key={name}>{humanize(name)}</span>)}
              {!stage.labels.length && <span className="muted">Not recorded</span>}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title={`${stage.title} — confusion matrix`} subtitle="Deployed candidate on the held-out evaluation split">
          {deployed?.confusion_matrix?.length ? (
            <ConfusionMatrix matrix={deployed.confusion_matrix} labels={stage.labels} />
          ) : (
            <EmptyState title="No confusion matrix" detail="This stage did not record a matrix in its evaluation." icon={<Icon name="target" />} />
          )}
        </Panel>
      </div>

      <Panel title={`${stage.title} — candidate algorithms`} subtitle="Every algorithm evaluated for this stage during training" flush>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Family</th>
                <th>Status</th>
                {metricColumns(stage).map((column) => <th key={column.key}>{column.label}</th>)}
                <th>Artifact size</th>
                <th>Hyperparameters</th>
              </tr>
            </thead>
            <tbody>
              {stage.candidates.map((candidate) => (
                <tr key={candidate.algorithm} className={candidate.deployed ? "selected" : ""}>
                  <td className="cell-strong">{humanize(candidate.algorithm)}</td>
                  <td className="muted">{candidate.profile.family}</td>
                  <td>{candidate.deployed ? <Badge value="DEPLOYED" tone="success" /> : <Badge value="EVALUATED" tone="neutral" />}</td>
                  {metricColumns(stage).map((column) => (
                    <td key={column.key} className="mono">{formatMetric(column.key, candidate.metrics[column.key])}</td>
                  ))}
                  <td className="mono muted">{bytes(candidate.model_size_bytes)}</td>
                  <td>
                    <div className="chip-row">
                      {Object.entries(candidate.hyperparameters).map(([name, value]) => (
                        <span className="chip" key={name}>{humanize(name)} <strong>{scalar(value)}</strong></span>
                      ))}
                      {!Object.keys(candidate.hyperparameters).length && <span className="muted">Not recorded</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Pipeline configuration" subtitle="Thresholds and fusion weights the runtime applies">
        <div className="grid-2">
          <dl className="kv-list">
            {Object.entries(catalog.pipeline.thresholds).map(([key, value]) => (
              <KV key={key} k={humanize(key)} v={<span className="mono">{scalar(value)}</span>} />
            ))}
          </dl>
          <dl className="kv-list">
            <KV k="Fusion strategy" v={<span className="mono">{scalar(catalog.pipeline.fusion.strategy)}</span>} />
            {Object.entries((catalog.pipeline.fusion.source_weights ?? {}) as Record<string, number>).map(([key, value]) => (
              <KV key={key} k={`Weight · ${humanize(key)}`} v={<span className="mono">{scalar(value)}</span>} />
            ))}
            <KV k="Evidence floor" v={<span className="mono">{scalar(catalog.pipeline.fusion.supporting_evidence_minimum_risk)}</span>} />
          </dl>
        </div>
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Comparison
 * ------------------------------------------------------------------ */
function ComparisonTab({ catalog, error }: { catalog?: ModelCatalog; error?: string }) {
  const [scope, setScope] = useState<"stages" | "ensembles" | "benchmark">("stages");

  if (error) return <EmptyState title="Model catalog unavailable" detail={error} icon={<Icon name="models" />} />;
  if (!catalog) return <EmptyState title="Reading artifacts" detail="Loading evaluation records for every trained candidate." icon={<Icon name="models" />} />;

  const algorithms = [...new Set(catalog.stages.flatMap((stage) => stage.candidates.map((candidate) => candidate.algorithm)))];

  const scatter = catalog.stages.flatMap((stage) =>
    stage.candidates
      .filter((candidate) => candidate.metrics.inference_p50_ms !== undefined)
      .map((candidate) => ({
        x: candidate.metrics.inference_p50_ms,
        y: candidate.metrics.accuracy ?? candidate.metrics.top1_accuracy ?? 0,
        label: `${stage.title} · ${humanize(candidate.algorithm)}${candidate.deployed ? " (deployed)" : ""}`,
        color: colorFor(stage.stage)
      }))
  );

  return (
    <div className="stack">
      <div className="toolbar">
        <Segmented<"stages" | "ensembles" | "benchmark">
          value={scope}
          onChange={setScope}
          options={[
            { value: "stages", label: "Pipeline stages" },
            { value: "ensembles", label: "Expert ensembles" },
            { value: "benchmark", label: "Architecture benchmark" }
          ]}
        />
        <span className="toolbar-count">
          {algorithms.length} algorithms across {catalog.stages.length} stages, every recorded metric
        </span>
      </div>

      {scope === "stages" && (
        <>
          {COMPARABLE_METRICS.map((definition) => {
            const stagesWithMetric = catalog.stages.filter((stage) =>
              stage.candidates.some((candidate) => candidate.metrics[definition.key] !== undefined)
            );
            if (!stagesWithMetric.length) return null;
            const series = algorithms
              .map((algorithm, index) => ({
                name: humanize(algorithm),
                color: colorFor(algorithm, index + 3),
                values: stagesWithMetric.map((stage) => stage.candidates.find((candidate) => candidate.algorithm === algorithm)?.metrics[definition.key] ?? 0)
              }))
              .filter((entry) => entry.values.some((value) => value > 0));
            const domainMax = definition.kind === "ratio" ? 1 : undefined;
            return (
              <Panel
                key={definition.key}
                title={`${definition.label} across pipeline stages`}
                subtitle={definition.kind === "ratio"
                  ? "Every candidate algorithm evaluated for each stage, higher is better"
                  : "Measured during evaluation, lower is better"}
              >
                <GroupedBarChart
                  groups={stagesWithMetric.map((stage) => stage.title)}
                  series={series}
                  height={230}
                  domainMax={domainMax}
                  format={(value) => (definition.kind === "ratio" ? `${(value * 100).toFixed(1)}%` : `${value.toFixed(1)}ms`)}
                />
              </Panel>
            );
          })}

          <div className="grid-2">
            <Panel title="Accuracy against inference cost" subtitle="Each point is one trained candidate">
              <ScatterChart points={scatter} xLabel="Inference p50 (ms)" yLabel="Accuracy" height={250} />
            </Panel>
            <Panel title="Deployed selection" subtitle="What the runtime actually serves for each stage">
              <RankedBars
                data={catalog.stages.map((stage) => {
                  const deployed = stage.candidates.find((candidate) => candidate.deployed);
                  return {
                    label: `${stage.title} · ${humanize(stage.deployment.algorithm)}`,
                    value: Number((deployed?.metrics.accuracy ?? deployed?.metrics.top1_accuracy ?? 0).toFixed(4))
                  };
                })}
                format={(value) => percent(value, 2)}
              />
            </Panel>
          </div>

          <Panel title="Full evaluation record" subtitle="Every metric written during training, per stage and candidate" flush>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Stage</th>
                    <th>Algorithm</th>
                    <th>Accuracy</th>
                    <th>F1 macro</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>ROC AUC</th>
                    <th>p50</th>
                    <th>p95</th>
                    <th>Size</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.stages.flatMap((stage) =>
                    stage.candidates.map((candidate) => (
                      <tr key={`${stage.stage}-${candidate.algorithm}`} className={candidate.deployed ? "selected" : ""}>
                        <td className="cell-strong">{stage.title}</td>
                        <td>
                          {humanize(candidate.algorithm)}
                          {candidate.deployed && <span className="cell-sub">deployed</span>}
                        </td>
                        <td className="mono">{formatMetric("accuracy", candidate.metrics.accuracy ?? candidate.metrics.top1_accuracy)}</td>
                        <td className="mono">{formatMetric("f1_macro", candidate.metrics.f1_macro)}</td>
                        <td className="mono">{formatMetric("precision_macro", candidate.metrics.precision_macro)}</td>
                        <td className="mono">{formatMetric("recall_macro", candidate.metrics.recall_macro)}</td>
                        <td className="mono">{formatMetric("roc_auc", candidate.metrics.roc_auc)}</td>
                        <td className="mono muted">{formatMetric("inference_p50_ms", candidate.metrics.inference_p50_ms)}</td>
                        <td className="mono muted">{formatMetric("inference_p95_ms", candidate.metrics.inference_p95_ms)}</td>
                        <td className="mono muted">{bytes(candidate.model_size_bytes)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}

      {scope === "ensembles" && (
        catalog.ensembles.length ? (
          <div className="stack">
            {catalog.ensembles.map((family) => (
              <Panel key={family.family} title={`${humanize(family.family)} expert ensembles`} subtitle={`Run ${family.run_id} · retained combinations are marked`}>
                <GroupedBarChart
                  groups={family.combinations.map((combination) => combination.members.map((member) => member.split("_")[0]).join("+"))}
                  height={230}
                  domainMax={1}
                  format={(value) => `${(value * 100).toFixed(1)}%`}
                  series={[
                    { name: "F1 macro", color: "#3b82f6", values: family.combinations.map((combination) => combination.metrics.f1_macro ?? 0) },
                    { name: "Accuracy", color: "#2bd576", values: family.combinations.map((combination) => combination.metrics.accuracy ?? 0) },
                    { name: "Recall", color: "#a855f7", values: family.combinations.map((combination) => combination.metrics.recall_macro ?? 0) }
                  ]}
                />
                <div className="table-wrap" style={{ marginTop: 14 }}>
                  <table>
                    <thead>
                      <tr><th>Members</th><th>Retained</th><th>Accuracy</th><th>F1 macro</th><th>p50</th><th>p95</th></tr>
                    </thead>
                    <tbody>
                      {family.combinations.map((combination, index) => (
                        <tr key={index}>
                          <td className="mono">{combination.members.map(humanize).join(" + ")}</td>
                          <td><Badge value={combination.retained ? "RETAINED" : "REJECTED"} tone={combination.retained ? "success" : "neutral"} /></td>
                          <td className="mono">{formatMetric("accuracy", combination.metrics.accuracy)}</td>
                          <td className="mono">{formatMetric("f1_macro", combination.metrics.f1_macro)}</td>
                          <td className="mono muted">{formatMetric("inference_p50_ms", combination.metrics.inference_p50_ms)}</td>
                          <td className="mono muted">{formatMetric("inference_p95_ms", combination.metrics.inference_p95_ms)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            ))}
          </div>
        ) : (
          <EmptyState title="No ensemble evaluations" detail="Ensemble comparisons appear once the ensemble evaluation stage has been run." icon={<Icon name="layers" />} />
        )
      )}

      {scope === "benchmark" && <BenchmarkView catalog={catalog} />}
    </div>
  );
}

function BenchmarkView({ catalog }: { catalog: ModelCatalog }) {
  const summary = catalog.benchmark.summary as Record<string, unknown>;
  if (!Object.keys(summary).length && !catalog.benchmark.runs.length) {
    return <EmptyState title="No benchmark record" detail="Run the pipeline benchmark to compare architecture variants." icon={<Icon name="activity" />} />;
  }
  const variants = (summary.architecture_variants as string[] | undefined) ?? [];
  const adaptive = (summary.adaptive_variants as string[] | undefined) ?? [];
  const ablations = (summary.ablations as string[] | undefined) ?? [];

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Requests replayed" value={Number(summary.total_requests ?? 0)} detail={`${(summary.scenarios as string[] | undefined)?.length ?? 0} scenarios`} tone="info" />
        <Metric label="Latency p95" value={milliseconds(Number(summary.latency_p95_ms ?? 0), 1)} detail={`p50 ${milliseconds(Number(summary.latency_p50_ms ?? 0), 1)}`} tone="violet" />
        <Metric label="Throughput" value={`${Number(summary.throughput_requests_per_second ?? 0).toFixed(2)}/s`} detail="Sustained during the replay" tone="success" />
        <Metric label="F1" value={percent(Number(summary.f1 ?? 0), 1)} detail={`precision ${percent(Number(summary.precision ?? 0), 0)} · recall ${percent(Number(summary.recall ?? 0), 0)}`} tone="warning" />
      </div>
      <div className="grid-3">
        <Panel title="Architecture variants compared">
          <div className="chip-row">{variants.map((variant) => <span className="chip" key={variant}>{humanize(variant)}</span>)}</div>
        </Panel>
        <Panel title="Adaptive routing variants">
          <div className="chip-row">{adaptive.map((variant) => <span className="chip" key={variant}>{humanize(variant)}</span>)}</div>
        </Panel>
        <Panel title="Ablations">
          <div className="chip-row">{ablations.map((variant) => <span className="chip" key={variant}>{humanize(variant)}</span>)}</div>
        </Panel>
      </div>
      {catalog.benchmark.runs.map((run) => (
        <Panel key={run.run_id} title={`Benchmark run ${run.run_id}`}>
          <pre className="code-block">{JSON.stringify(run.metrics, null, 2)}</pre>
        </Panel>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Playground — query the pipeline directly
 * ------------------------------------------------------------------ */
function PlaygroundTab() {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/search");
  const [query, setQuery] = useState("q=1' OR '1'='1");
  const [body, setBody] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DetectionEvidence>();
  const [error, setError] = useState<string>();

  const run = async () => {
    setRunning(true);
    setError(undefined);
    try {
      const response = await detectBatch([{ label: "Manual probe", method, path, query, body, expected: "" }]);
      const entry = response.results[0];
      if (entry?.detection) setResult(entry.detection);
      else setError(entry?.error ?? "The detection service returned no evidence");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "detection service unavailable");
    } finally {
      setRunning(false);
    }
  };

  const flow = useMemo(
    () =>
      result
        ? buildFlow(
            {
              eventId: "probe", id: 0, occurredAt: new Date().toISOString(), category: "probe",
              method, path, query, statusCode: 200, risk: result.risks.overall,
              predictedAttack: result.predicted_attack, action: "PROBE", confidence: 0,
              detectionLatencyMs: result.total_latency_ms, upstreamLatencyMs: 0, gatewayLatencyMs: result.total_latency_ms,
              deepModelUsed: result.deep_model_used, detailsJson: "{}", sourceIp: "console"
            },
            result
          )
        : [],
    [result, method, path, query]
  );

  return (
    <div className="stack">
      <Panel title="Query the pipeline directly" subtitle="Sends one request to the detection service without enforcement, so every stage output is visible">
        <div className="form-grid">
          <label className="field">
            Method
            <select value={method} onChange={(event) => setMethod(event.target.value)}>
              {["GET", "POST", "PUT", "DELETE", "PATCH"].map((entry) => <option key={entry}>{entry}</option>)}
            </select>
          </label>
          <label className="field">
            Path
            <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/search" />
          </label>
          <label className="field" style={{ gridColumn: "span 2" }}>
            Query string
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="q=value" />
          </label>
        </div>
        <label className="field" style={{ marginTop: 14 }}>
          Body
          <textarea rows={3} value={body} onChange={(event) => setBody(event.target.value)} placeholder='{"field":"value"}' />
        </label>
        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => void run()} disabled={running || !path.startsWith("/")}>
            {running ? <span className="spinner" /> : <Icon name="play" size={13} />}
            {running ? "Evaluating" : "Evaluate"}
          </button>
          <div className="chip-row">
            {PROBE_LIBRARY.filter((probe) => probe.family !== "Baseline").slice(0, 6).map((probe) => (
              <button
                key={probe.label}
                className="chip"
                onClick={() => { setMethod(probe.method); setPath(probe.path); setQuery(probe.query ?? ""); setBody(probe.body ?? ""); }}
              >
                <i className="dot" style={{ background: colorFor(probe.expected) }} />
                {probe.label}
              </button>
            ))}
          </div>
        </div>
        {error && <p style={{ marginTop: 12, color: "var(--danger)", fontSize: 12 }}>{error}</p>}
      </Panel>

      {result && (
        <>
          <div className="grid-4 stagger">
            <Metric label="Classification" value={humanize(result.predicted_attack)} detail={`triage ${humanize(result.triage.decision)}`} tone="danger" />
            <Metric label="Fused risk" value={percent(result.risks.overall, 2)} detail={`http ${percent(result.risks.http, 1)}`} tone="warning" />
            <Metric label="Inference" value={milliseconds(result.total_latency_ms, 2)} detail={`${Object.keys(result.latency_by_stage_ms).length} stages`} tone="violet" />
            <Metric label="Deep escalation" value={result.deep_model_used ? "Yes" : "No"} detail={result.deep_output ? `confidence ${percent(result.deep_output.confidence, 1)}` : "Expert confidence sufficed"} tone={result.deep_model_used ? "info" : "success"} />
          </div>
          <Panel title="Stage-by-stage path" subtitle="Exactly which models ran, and what each decided">
            <RequestFlow nodes={flow} />
          </Panel>
          <div className="grid-2">
            <Panel title="Stage latency">
              <RankedBars
                data={Object.entries(result.latency_by_stage_ms).map(([stage, value]) => ({ label: humanize(stage), value: Number(value.toFixed(3)) }))}
                format={(value) => `${value.toFixed(3)} ms`}
                colorKey={(name) => colorFor(name)}
              />
            </Panel>
            <Panel title="Model versions consulted">
              <dl className="kv-list">
                {Object.entries(result.model_versions).map(([role, version]) => (
                  <KV key={role} k={humanize(role)} v={<span className="mono">{version}</span>} />
                ))}
              </dl>
            </Panel>
          </div>
          <Panel title="Raw detection response">
            <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
          </Panel>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Batch probing
 * ------------------------------------------------------------------ */
function BatchTab({ notify, refresh }: ViewProps) {
  const [families, setFamilies] = useState<string[]>(PROBE_FAMILIES);
  const [repeat, setRepeat] = useState(1);
  const [throughGateway, setThroughGateway] = useState(false);
  const [running, setRunning] = useState(false);
  const [batch, setBatch] = useState<BatchResponse>();
  const [gatewayResults, setGatewayResults] = useState<GatewayProbeResult[]>();

  const selectedProbes = useMemo(
    () => PROBE_LIBRARY.filter((probe) => families.includes(probe.family)),
    [families]
  );
  const expanded = useMemo(
    () => Array.from({ length: repeat }, () => selectedProbes).flat() as BatchProbe[],
    [selectedProbes, repeat]
  );

  const toggleFamily = (family: string) =>
    setFamilies((current) => (current.includes(family) ? current.filter((entry) => entry !== family) : [...current, family]));

  const run = async () => {
    if (!expanded.length) return;
    setRunning(true);
    setBatch(undefined);
    setGatewayResults(undefined);
    try {
      if (throughGateway) {
        const results: GatewayProbeResult[] = [];
        for (const probe of expanded) {
          results.push(await probeGateway(probe));
        }
        setGatewayResults(results);
        notify("Gateway replay complete", `${results.filter((entry) => entry.blocked).length} of ${results.length} mitigated`);
        await refresh();
      } else {
        const response = await detectBatch(expanded);
        setBatch(response);
        notify("Batch evaluated", `${response.summary.evaluated} probes scored in ${response.summary.total_latency_ms.toFixed(0)} ms`);
      }
    } catch (error) {
      notify("Batch failed", error instanceof Error ? error.message : "unknown error", "danger");
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="stack">
      <Panel
        title="Send a batch of attack payloads"
        subtitle={throughGateway
          ? "Replays each payload through the gateway, so enforcement, the upstream, and the event journal all participate"
          : "Evaluates each payload against the detection pipeline only — no enforcement and no journal entry"}
      >
        <div className="chip-row" style={{ marginBottom: 14 }}>
          {PROBE_FAMILIES.map((family) => {
            const active = families.includes(family);
            const count = PROBE_LIBRARY.filter((probe) => probe.family === family).length;
            return (
              <button
                key={family}
                className="chip"
                onClick={() => toggleFamily(family)}
                style={{
                  borderColor: active ? "var(--accent-line)" : undefined,
                  background: active ? "var(--accent-soft)" : undefined,
                  color: active ? "var(--text)" : undefined
                }}
              >
                <i className="dot" style={{ background: active ? "var(--accent)" : "var(--text-faint)" }} />
                {family} <strong>{count}</strong>
              </button>
            );
          })}
        </div>

        <div className="form-grid">
          <label className="field">
            Repetitions
            <select value={repeat} onChange={(event) => setRepeat(Number(event.target.value))}>
              {[1, 2, 3, 5].map((value) => <option key={value} value={value}>{value}×</option>)}
            </select>
          </label>
          <div className="field">
            Execution path
            <label style={{ display: "flex", alignItems: "center", gap: 9, height: 34, color: "var(--text)" }}>
              <Switch checked={throughGateway} onChange={setThroughGateway} label="Through the gateway" />
              {throughGateway ? "Through the gateway" : "Detection service only"}
            </label>
          </div>
          <div className="field">
            Batch size
            <div style={{ display: "flex", alignItems: "center", height: 34, fontFamily: "var(--mono)", color: "var(--text)" }}>
              {expanded.length} requests
            </div>
          </div>
        </div>

        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => void run()} disabled={running || !expanded.length}>
            {running ? <span className="spinner" /> : <Icon name="send" size={13} />}
            {running ? "Sending" : throughGateway ? "Replay through gateway" : "Evaluate batch"}
          </button>
          <button className="btn ghost" onClick={() => setFamilies(PROBE_FAMILIES)}>Select all</button>
          <button className="btn ghost" onClick={() => setFamilies([])}>Clear</button>
        </div>
      </Panel>

      {batch && <BatchResults batch={batch} />}
      {gatewayResults && <GatewayResults results={gatewayResults} />}

      <Panel title="Payload library" subtitle="Probe shapes available to the batch" flush>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Family</th><th>Probe</th><th>Method</th><th>Target</th><th>Expected class</th></tr></thead>
            <tbody>
              {PROBE_LIBRARY.map((probe) => (
                <tr key={`${probe.family}-${probe.label}`} className={families.includes(probe.family) ? "" : "muted"}>
                  <td>{probe.family}</td>
                  <td className="cell-strong">{probe.label}</td>
                  <td className="mono">{probe.method}</td>
                  <td className="mono muted">{probe.path}{probe.query ? `?${probe.query}` : ""}{probe.body ? ` ${probe.body}` : ""}</td>
                  <td>
                    <span className="chip">
                      <i className="dot" style={{ background: colorFor(probe.expected) }} />
                      {humanize(probe.expected)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function BatchResults({ batch }: { batch: BatchResponse }) {
  const summary = batch.summary;
  const perClass = useMemo(() => {
    const grouped = new Map<string, { total: number; matched: number }>();
    batch.results.forEach((entry) => {
      if (!entry.expected || !entry.detection) return;
      const bucket = grouped.get(entry.expected) ?? { total: 0, matched: 0 };
      bucket.total += 1;
      if (entry.matched) bucket.matched += 1;
      grouped.set(entry.expected, bucket);
    });
    return [...grouped.entries()];
  }, [batch]);

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Probes evaluated" value={summary.evaluated} detail={`${summary.failed} failed to evaluate`} tone="info" />
        <Metric label="Classification match" value={summary.accuracy === null ? "—" : percent(summary.accuracy, 1)} detail={`${summary.matched} of ${summary.scored} expected classes`} tone="success" />
        <Metric label="Deep escalations" value={summary.deep_escalations} detail={`mean risk ${percent(summary.mean_risk, 1)}`} tone="violet" />
        <Metric label="Inference p95" value={milliseconds(summary.latency_p95_ms, 2)} detail={`p50 ${milliseconds(summary.latency_p50_ms, 2)}`} tone="warning" />
      </div>

      <div className="grid-2">
        <Panel title="Predicted classes" subtitle="What the pipeline decided for this batch">
          <DonutChart data={sortedEntries(summary.attacks).map(([name, value]) => ({ label: humanize(name), value }))} centerLabel="probes" size={140} />
        </Panel>
        <Panel title="Per-class recall" subtitle="Share of probes classified as their expected class">
          <RankedBars
            data={perClass.map(([name, value]) => ({ label: humanize(name), value: Number((value.matched / value.total).toFixed(4)) }))}
            format={(value) => percent(value, 0)}
          />
        </Panel>
      </div>

      <Panel title="Routes taken" subtitle="Distinct pipeline paths exercised by this batch">
        <RankedBars
          data={sortedEntries(summary.routes).map(([route, value]) => ({
            label: route.split(" > ").map((step) => humanize(step).replace(" Fast", "")).join(" → "),
            value
          }))}
        />
      </Panel>

      <Panel title="Probe results" flush>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>Target</th><th>Expected</th><th>Predicted</th><th>Match</th><th>Risk</th><th>Confidence</th><th>Route</th><th>Latency</th></tr>
            </thead>
            <tbody>
              {batch.results.map((entry) => {
                const detection = entry.detection;
                const confidence = detection?.deep_output?.confidence ?? detection?.expert_outputs[0]?.confidence ?? detection?.triage.suspicious_probability;
                return (
                  <tr key={entry.index}>
                    <td className="mono muted">{entry.index + 1}</td>
                    <td className="mono">{entry.request.method} {entry.request.path}{entry.request.query ? `?${truncate(entry.request.query, 34)}` : ""}</td>
                    <td>{entry.expected ? humanize(entry.expected) : "—"}</td>
                    <td className="cell-strong">{detection ? humanize(detection.predicted_attack) : <span className="muted">{entry.error ?? "—"}</span>}</td>
                    <td>{entry.matched === null || entry.matched === undefined ? "—" : <Badge value={entry.matched ? "MATCH" : "MISS"} tone={entry.matched ? "success" : "danger"} />}</td>
                    <td className="mono">{detection ? percent(detection.risks.overall, 1) : "—"}</td>
                    <td className="mono muted">{confidence === undefined ? "—" : percent(confidence, 1)}</td>
                    <td className="mono faint" style={{ fontSize: 10.5 }}>{detection?.routing_path.map((step) => step.replace("_FAST", "")).join(" → ") ?? "—"}</td>
                    <td className="mono muted">{milliseconds(detection?.total_latency_ms, 1)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function GatewayResults({ results }: { results: GatewayProbeResult[] }) {
  const blocked = results.filter((entry) => entry.blocked).length;
  const failed = results.filter((entry) => entry.error).length;
  const meanRoundTrip = results.reduce((sum, entry) => sum + entry.roundTripMs, 0) / Math.max(1, results.length);

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Replayed" value={results.length} detail="Through the gateway to the demo upstream" tone="info" />
        <Metric label="Mitigated" value={blocked} detail={`${percent(blocked / Math.max(1, results.length), 0)} rejected before the upstream`} tone="danger" />
        <Metric label="Reached upstream" value={results.length - blocked - failed} detail="Forwarded and answered by the demo backend" tone="success" />
        <Metric label="Mean round trip" value={milliseconds(meanRoundTrip, 1)} detail="Measured in the browser" tone="violet" />
      </div>
      <Panel title="Gateway replay results" subtitle="Each probe travelled the full chain; matching journal entries appear in Live Attacks" flush>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Probe</th><th>Method</th><th>Target</th><th>Status</th><th>Outcome</th><th>Classification</th><th>Round trip</th><th>Request id</th></tr></thead>
            <tbody>
              {results.map((entry, index) => (
                <tr key={index}>
                  <td className="cell-strong">{entry.label}</td>
                  <td className="mono">{entry.method}</td>
                  <td className="mono muted">{truncate(entry.target, 44)}</td>
                  <td className="mono">{entry.status || "—"}</td>
                  <td>
                    {entry.error
                      ? <Badge value="ERROR" tone="danger" />
                      : <Badge value={entry.blocked ? "MITIGATED" : "FORWARDED"} tone={entry.blocked ? "danger" : "success"} />}
                  </td>
                  <td>{entry.predictedAttack ? humanize(entry.predictedAttack) : "—"}</td>
                  <td className="mono muted">{milliseconds(entry.roundTripMs, 1)}</td>
                  <td className="mono faint" style={{ fontSize: 10.5 }}>{entry.requestId?.slice(0, 8) ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Registry
 * ------------------------------------------------------------------ */
function RegistryTab({ snapshot, api, mutate }: ViewProps) {
  const runtime = snapshot.runtimeModels.models;
  return (
    <div className="stack">
      <Panel title="Serving right now" subtitle="Model versions the detection runtime reports as loaded">
        {Object.keys(runtime).length ? (
          <div className="grid-3">
            {Object.entries(runtime).map(([role, version]) => (
              <article className="stage-card" key={role}>
                <header>
                  <span className="dot" style={{ background: colorFor(role) }} />
                  <h3>{humanize(role)}</h3>
                </header>
                <strong className="mono" style={{ fontSize: 12 }}>{version}</strong>
                <p>Loaded in the detection service runtime</p>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="Runtime models unavailable" detail="The detection service did not report loaded artifacts." icon={<Icon name="models" />} />
        )}
      </Panel>

      <Panel title="Governed model registry" subtitle="Promotion, assignment, approval, and retirement are all audit logged" flush>
        {snapshot.models.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Model</th><th>Artifact version</th><th>Lifecycle</th><th>Recorded metrics</th><th>Actions</th></tr></thead>
              <tbody>
                {snapshot.models.map((model) => {
                  const metrics = JSON.parse(model.metricsJson || "{}") as Record<string, unknown>;
                  return (
                    <tr key={model.modelVersionId}>
                      <td className="cell-strong">{model.modelName}</td>
                      <td className="mono muted">{model.artifactVersion}</td>
                      <td><Badge value={model.status} /></td>
                      <td>
                        <div className="chip-row">
                          {Object.entries(metrics).slice(0, 4).map(([name, value]) => (
                            <span className="chip" key={name}>{humanize(name)} <strong>{formatMetric(name, Number(value))}</strong></span>
                          ))}
                          {!Object.keys(metrics).length && <span className="muted">No metrics recorded</span>}
                        </div>
                      </td>
                      <td className="actions">
                        {model.status !== "ACTIVE" && (
                          <button className="btn small" onClick={() => void mutate(() => api.promote(model.modelVersionId), `${model.modelName} promoted to active.`)}>Promote</button>
                        )}
                        {model.status === "CHALLENGER" && (
                          <button className="btn small" onClick={() => void mutate(() => api.approve(model.modelVersionId), `${model.modelName} approved.`)}>Approve</button>
                        )}
                        <button className="btn small" onClick={() => void mutate(() => api.assign(model.modelVersionId), `${model.modelName} assigned to the default application.`)}>Assign</button>
                        {model.status !== "RETIRED" && (
                          <button className="btn small danger" onClick={() => void mutate(() => api.retire(model.modelVersionId), `${model.modelName} retired.`)}>Retire</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="Registry is empty" detail="Candidates appear here after the adaptation service registers a training run." icon={<Icon name="models" />} />
        )}
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */
function metricColumns(stage: CatalogStage) {
  const available = new Set(stage.candidates.flatMap((candidate) => Object.keys(candidate.metrics)));
  return COMPARABLE_METRICS.filter((column) => available.has(column.key));
}

function formatMetric(name: string, value?: number): string {
  if (value === undefined || value === null || !Number.isFinite(value)) return "—";
  const key = name.toLowerCase();
  if (key.includes("_ms") || key.includes("latency")) return `${value.toFixed(2)} ms`;
  if (key.includes("size")) return bytes(value);
  if (["accuracy", "f1", "recall", "precision", "auc", "coverage", "rate", "top1", "top2", "ece", "risk", "confidence"].some((token) => key.includes(token))) {
    return `${(value * 100).toFixed(value >= 0.9995 ? 3 : 2)}%`;
  }
  if (Math.abs(value) < 0.001 && value !== 0) return value.toExponential(2);
  return value.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
}

function truncate(value: string, size: number) {
  return value.length > size ? `${value.slice(0, size - 1)}…` : value;
}
