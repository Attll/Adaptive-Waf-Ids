import { useCallback, useEffect, useState } from "react";
import { escalations as fetchEscalations, type EscalationOutcome, type EscalationStatistics } from "../api";
import { DonutChart, RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Switch } from "../components/Ui";
import { colorFor, formatTime, label as humanize, milliseconds, percent, relativeTime, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

/**
 * A request the fast experts were unsure about is answered immediately and adjudicated by the deep model
 * afterwards. This page shows what was allowed provisionally and what the deep model eventually concluded.
 */
export function Escalations({ refreshInterval }: ViewProps) {
  const [offset,setOffset]=useState(0),[jobs,setJobs]=useState<{job_id:string;request_id:string;state:string;model_version:string;outcome:unknown}[]>([]),[jobError,setJobError]=useState('');
  useEffect(()=>{let active=true;const poll=async()=>{try{const response=await fetch(`/detection-api/v1/deep/jobs?limit=50&offset=${offset}`);if(!response.ok)throw Error(`Job history HTTP ${response.status}`);const result=await response.json();if(active){setJobs(result.jobs);setJobError('');}}catch(e){if(active)setJobError(String(e));}};void poll();const timer=window.setInterval(()=>void poll(),3000);return()=>{active=false;clearInterval(timer);};},[offset]);
  const [outcomes, setOutcomes] = useState<EscalationOutcome[]>([]);
  const [statistics, setStatistics] = useState<EscalationStatistics>();
  const [error, setError] = useState<string>();
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<EscalationOutcome>();

  const load = useCallback(async () => {
    try {
      const response = await fetchEscalations(100);
      setOutcomes(response.escalations);
      setStatistics(response.statistics);
      setError(undefined);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "detection service unavailable");
    }
  }, []);

  useEffect(() => {
    void load();
    if (!live) return;
    const timer = window.setInterval(() => void load(), Math.max(3, Math.min(refreshInterval || 5, 15)) * 1000);
    return () => window.clearInterval(timer);
  }, [load, live, refreshInterval]);

  if (error) {
    return (
      <Panel title="Deep escalation queue" action={<Badge value="UNAVAILABLE" tone="danger" />}>
        <EmptyState title="Detection service unreachable" detail={error} icon={<Icon name="layers" />} />
      </Panel>
    );
  }

  if (statistics && !statistics.enabled) {
    return (
      <Panel title="Deep escalation queue" action={<Badge value="INLINE" tone="neutral" />}>
        <EmptyState
          title="Escalation runs inline"
          detail="asynchronous_deep_escalation_enabled is false in configs/models/pipeline.toml, so the deep model runs inside the request path and there is no queue to show."
          icon={<Icon name="layers" />}
        />
      </Panel>
    );
  }

  const active = selected ?? outcomes[0];
  const changed = outcomes.filter((entry) => entry.changed);
  const failed = outcomes.filter((entry) => entry.error);

  return (
    <div className="stack">
      <Panel title="All deferred jobs" subtitle="Persistent job history, including pending, running, failed and expired requests. New arrivals can shift offset pages; request and job IDs identify each result."><div className="btn-row"><button className="btn" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-50))}>Previous jobs</button><Badge value={`Rows ${offset+1}–${offset+jobs.length}`} tone="info"/><button className="btn" disabled={jobs.length<50} onClick={()=>setOffset(offset+50)}>Next jobs</button></div>{jobError&&<p role="alert">{jobError}</p>}<div className="table-wrap"><table><thead><tr><th>Request / job</th><th>State</th><th>Model version</th><th>Deep result, probabilities and timing</th></tr></thead><tbody>{jobs.map(job=><tr key={job.job_id}><td className="mono">{job.request_id}<br/>{job.job_id}</td><td><Badge value={job.state} tone="info"/></td><td>{job.model_version}</td><td><details><summary>Inspect result</summary><pre className="code-block">{JSON.stringify(job.outcome,null,2)}</pre></details></td></tr>)}</tbody></table></div></Panel>
      <div className="grid-4 stagger">
        <Metric
          label="Deferred and resolved"
          value={statistics?.resolved ?? 0}
          detail={`${statistics?.submitted ?? 0} submitted · ${statistics?.rejected ?? 0} rejected when full`}
          tone="info"
          icon={<Icon name="layers" size={13} />}
        />
        <Metric
          label="Verdicts revised"
          value={statistics?.verdict_changed ?? 0}
          detail={outcomes.length ? `${percent(changed.length / outcomes.length, 1)} of retained adjudications` : "nothing adjudicated yet"}
          tone={changed.length ? "danger" : "success"}
          icon={<Icon name="alert" size={13} />}
        />
        <Metric
          label="Pending deep jobs"
          value={statistics?.pending ?? statistics?.queue_depth ?? 0}
          detail={`${statistics?.queue_depth ?? 0} waiting · ${statistics?.running ?? 0} running · limit ${statistics?.queue_limit ?? 0}`}
          tone={(statistics?.queue_depth ?? 0) > 0 ? "warning" : "success"}
          icon={<Icon name="bolt" size={13} />}
        />
        <Metric
          label="Median deep latency"
          value={milliseconds(statistics?.median_deep_latency_ms, 1)}
          detail={`mean wait in queue ${milliseconds(statistics?.mean_queued_ms, 1)}`}
          tone="violet"
          icon={<Icon name="clock" size={13} />}
        />
      </div>

      <Panel
        title="How deferred escalation works"
        subtitle="Deep evidence arrives later; it can affect future requests but cannot undo a completed operation"
        action={
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11.5, color: "var(--text-secondary)" }}>
            <Switch checked={live} onChange={setLive} label="Live refresh" />
            Live
          </label>
        }
      >
        <div className="flow">
          {[
            { title: "Fast experts", body: "Confidence below the threshold", tone: "#f5a524" },
            { title: "Answer immediately", body: "Caller gets the fast verdict; request allowed provisionally", tone: "#2bd576" },
            { title: "Background worker", body: `Queued for one of ${statistics?.workers ?? 0} deep workers`, tone: "#3b82f6" },
            { title: "Deep adjudication", body: "Transformer re-classifies the same request", tone: "#22d3ee" },
            { title: "Revised verdict", body: "Journalled and streamed to the console", tone: "#a855f7" }
          ].map((node, index) => (
            <article key={node.title} className="flow-node active" style={{ ["--node-tone" as string]: node.tone, animationDelay: `${index * 0.06}s` }}>
              <header>
                <span className="idx">{index + 1}</span>
                <h4>{node.title}</h4>
              </header>
              <p className="verdict" style={{ color: node.tone, fontSize: 11.5 }}>{node.body}</p>
            </article>
          ))}
        </div>
      </Panel>

      {outcomes.length === 0 ? (
        <Panel title="Adjudications">
          <EmptyState
            title="Nothing has been deferred yet"
            detail="A request only defers when a fast expert falls below the confidence threshold. Generate traffic to produce some."
            icon={<Icon name="layers" />}
          />
        </Panel>
      ) : (
        <>
          <div className="grid-2">
            <Panel title="Revised against confirmed" subtitle="Did the deep model agree with the fast verdict?">
              <DonutChart
                size={140}
                centerLabel="adjudications"
                data={[
                  { label: "Confirmed", value: outcomes.length - changed.length - failed.length },
                  { label: "Revised", value: changed.length },
                  { label: "Failed", value: failed.length }
                ].filter((entry) => entry.value > 0)}
              />
            </Panel>
            <Panel title="Revised classes" subtitle="What the deep model concluded when it disagreed">
              {changed.length ? (
                <RankedBars
                  data={sortedEntries(changed.reduce<Record<string, number>>((result, entry) => {
                    const key = `${entry.provisional.predicted_attack} → ${entry.revised.predicted_attack}`;
                    result[key] = (result[key] ?? 0) + 1;
                    return result;
                  }, {})).map(([name, value]) => ({ label: name, value }))}
                />
              ) : (
                <EmptyState title="No revisions" detail="Every deferred request was confirmed by the deep model." icon={<Icon name="check" />} />
              )}
            </Panel>
          </div>

          <div className="split">
            <Panel title="Adjudications" subtitle="Newest first" tight>
              <div className="live-feed">
                {outcomes.map((entry) => (
                  <article
                    key={entry.escalation_id}
                    className={`live-card${active?.escalation_id === entry.escalation_id ? " selected" : ""}`}
                    onClick={() => setSelected(entry)}
                  >
                    <div className="top">
                      <span className="dot" style={{ background: colorFor(entry.revised.predicted_attack) }} />
                      <strong style={{ fontSize: 12 }}>{humanize(entry.revised.predicted_attack)}</strong>
                      <Badge
                        value={entry.error ? "FAILED" : entry.changed ? "REVISED" : "CONFIRMED"}
                        tone={entry.error ? "danger" : entry.changed ? "warning" : "success"}
                      />
                      <span className="when">{formatTime(entry.resolved_at)}</span>
                    </div>
                    <div className="target">{entry.method} {entry.path}{entry.query ? `?${entry.query}` : ""}</div>
                    <div className="facts">
                      <span>was <b>{humanize(entry.provisional.predicted_attack)}</b></span>
                      <span>confidence <b>{percent(entry.provisional.confidence, 1)}</b> → <b>{percent(entry.revised.confidence, 1)}</b></span>
                      <span>queued <b>{milliseconds(entry.queued_ms, 1)}</b></span>
                      <span>deep <b>{milliseconds(entry.deep_latency_ms, 1)}</b></span>
                    </div>
                  </article>
                ))}
              </div>
            </Panel>

            {active && (
              <div className="stack">
                <Panel
                  title="Adjudication detail"
                  subtitle={active.changed
                    ? "The deep model disagreed with the fast verdict after the request had already been allowed"
                    : "The deep model confirmed the fast verdict"}
                  action={<Badge value={active.changed ? "REVISED" : "CONFIRMED"} tone={active.changed ? "warning" : "success"} />}
                >
                  <div className="grid-2" style={{ gap: 12, marginBottom: 14 }}>
                    <Metric label="Provisional verdict" value={humanize(active.provisional.predicted_attack)} detail={`${percent(active.provisional.confidence, 2)} confidence · ${percent(active.provisional.risk, 2)} risk`} tone="warning" />
                    <Metric label="Deep verdict" value={humanize(active.revised.predicted_attack)} detail={`${percent(active.revised.confidence, 2)} confidence · ${percent(active.revised.risk, 2)} risk`} tone={active.changed ? "danger" : "success"} />
                  </div>
                  <dl className="kv-list">
                    <KV k="Request" v={<span className="mono">{active.method} {active.path}</span>} />
                    <KV k="Query" v={<span className="mono" style={{ fontSize: 11 }}>{active.query || "—"}</span>} />
                    <KV k="Source" v={<span className="mono">{active.source_ip ?? "—"}</span>} />
                    <KV k="Request id" v={<span className="mono faint">{active.request_id}</span>} />
                    <KV k="Waited in queue" v={milliseconds(active.queued_ms, 2)} />
                    <KV k="Deep inference" v={milliseconds(active.deep_latency_ms, 2)} />
                    <KV k="Deep model" v={<span className="mono">{active.revised.model_version}</span>} />
                    <KV k="Resolved" v={`${formatTime(active.resolved_at)} · ${relativeTime(active.resolved_at)}`} />
                    {active.error && <KV k="Error" v={<span style={{ color: "var(--danger)" }}>{active.error}</span>} />}
                  </dl>
                </Panel>

                {Object.keys(active.revised.class_scores ?? {}).length > 0 && (
                  <Panel title="Deep model class scores" subtitle="Full probability distribution from the adjudicating model">
                    <RankedBars
                      data={Object.entries(active.revised.class_scores).map(([name, score]) => ({ label: humanize(name), value: Number(score.toFixed(6)) }))}
                      format={(value) => percent(value, 2)}
                    />
                  </Panel>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
