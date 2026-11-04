import { useEffect, useState } from "react";
import { EmptyState, Metric, Panel } from "../components/Ui";
import { milliseconds } from "../lib/format";
import type { ViewProps } from "../lib/view";

type Telemetry = {
  completed_inference_rps: number;
  fully_inspected_rps: number;
  model_versions: Record<string,string>;
  coverage_since_start: Record<string,number>;
  routes_since_start: Record<string,number>;
  stage_latency_ms: Record<string,{count_retained:number;p50:number;p95:number}>;
  deep_queue: {enabled?:boolean;backend?:string;pending?:number;running?:number;failed?:number;expired?:number};
  process: {cpu_seconds?:number;rss_bytes?:number};
  gpu: {available:boolean;allocated_bytes?:number;utilization_percent?:number|null};
  research_monitoring: {verified_labels:number;verified_ece:number|null;risk_psi:number|null;conformal_set_count:number;conformal_mean_set_size:number|null;bandit_reward:number|null;reason:string};
  context: {available:boolean;mode?:string;sessions_retained?:number;revisions_retained?:number;endpoints?:number;verified_profile_observations?:number;persistence?:string};
  policy_lifecycle: {available:boolean;activation_enabled:boolean;active_version?:string;events:{timestamp:string;action:string;version:string}[]};
};

export function Research({refreshInterval,snapshot}: ViewProps) {
  const [data,setData] = useState<Telemetry>();
  const [error,setError] = useState<string>();
  const [experiments,setExperiments] = useState<{mode:string;concurrency:number;metrics:Record<string,number|null>}[]>([]);
  useEffect(() => {
    let active=true;
    const load=async()=>{
      try {
        const response=await fetch("/detection-api/v1/research/telemetry");
        if(!response.ok) throw new Error(`Telemetry returned ${response.status}`);
        const value=await response.json() as Telemetry;
        if(active){setData(value);setError(undefined);}
        const measured=await fetch("/detection-api/v1/research/results");
        if(measured.ok){const body=await measured.json();if(active)setExperiments(body.report?.experiments??[]);}
      } catch(reason){if(active)setError(reason instanceof Error?reason.message:"Telemetry unavailable");}
    };
    void load();
    const timer=window.setInterval(()=>void load(),Math.max(3,refreshInterval)*1000);
    return()=>{active=false;window.clearInterval(timer);};
  },[refreshInterval]);
  if(error) return <Panel title="Research runtime"><EmptyState title="Telemetry unavailable" detail={error}/></Panel>;
  if(!data) return <Panel title="Research runtime"><p>Loading measured runtime telemetry…</p></Panel>;
  return <div className="stack">
    <Panel title="Live inference telemetry"><p>Detection API observations over a 60-second window. Experimental benchmark results are recorded separately.</p></Panel>
    <div className="grid-4">
      <Metric label="Completed inference / s" value={data.completed_inference_rps.toFixed(2)} detail="Detection API scope"/>
      <Metric label="Fully inspected / s" value={data.fully_inspected_rps.toFixed(2)} detail="Rules-only and provisional results excluded"/>
      <Metric label="Pending deep jobs" value={data.deep_queue.pending??0} detail={data.deep_queue.enabled===false?"Inline / queue disabled":`${data.deep_queue.running??0} running · ${data.deep_queue.backend??"in-process"}`}/>
      <Metric label="GPU allocated" value={data.gpu.available?`${((data.gpu.allocated_bytes??0)/1048576).toFixed(1)} MiB`:"CPU / unavailable"} detail="Allocator observation; GPU utilization is not sampled"/>
    </div>
    <div className="grid-3">
      <Metric label="Process CPU time" value={data.process.cpu_seconds===undefined?"Unavailable":`${data.process.cpu_seconds.toFixed(1)} s`} detail="Cumulative detection process CPU; not system utilization"/>
      <Metric label="Process resident memory" value={data.process.rss_bytes===undefined?"Unavailable":`${(data.process.rss_bytes/1048576).toFixed(1)} MiB`} detail="Detection process RSS"/>
      <Metric label="Gateway enforcement policy" value={`v${snapshot.gatewayPolicy.version}`} detail={`Block threshold ${snapshot.gatewayPolicy.blockRiskThreshold} · rate limit ${snapshot.gatewayPolicy.rateLimitShortWindow}`}/>
    </div>
    <Panel title="Active runtime versions"><dl>{Object.entries(data.model_versions).map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl></Panel>
    <Panel title="Per-stage latency"><table><thead><tr><th>Stage</th><th>Retained samples</th><th>p50</th><th>p95</th></tr></thead><tbody>{Object.entries(data.stage_latency_ms).map(([name,value])=><tr key={name}><td>{name}</td><td>{value.count_retained}</td><td>{milliseconds(value.p50)}</td><td>{milliseconds(value.p95)}</td></tr>)}</tbody></table></Panel>
    <Panel title="Inspection coverage since start"><dl>{Object.entries(data.coverage_since_start).map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl></Panel>
    <Panel title="Executed routes since start"><dl>{Object.entries(data.routes_since_start).map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl></Panel>
    <Panel title="Uncertainty and verified monitoring">
      <p>{data.research_monitoring.verified_labels} verified labels retained · ECE {data.research_monitoring.verified_ece?.toFixed(4)??"unavailable"} · Risk PSI {data.research_monitoring.risk_psi?.toFixed(4)??"reviewed reference required"}</p>
      <p>{data.research_monitoring.conformal_set_count} conformal sets observed · Mean size {data.research_monitoring.conformal_mean_set_size?.toFixed(2)??"unavailable"}</p>
      <p>{data.research_monitoring.reason}</p>
    </Panel>
    <Panel title="Delayed context">
      {data.context.available?<><p>{data.context.mode} · {data.context.sessions_retained} sessions · {data.context.revisions_retained} retained revisions · {data.context.endpoints} profiled endpoints · {data.context.verified_profile_observations} reviewed benign observations</p><p>{data.context.persistence}</p></>:<p>Session reconciliation and endpoint context are disabled in this runtime.</p>}
    </Panel>
    <Panel title="Policy activation history">
      <p>{data.policy_lifecycle.activation_enabled?"Explicit activation flag enabled":"Live promotion disabled"} · Active candidate {data.policy_lifecycle.active_version??"configured startup baseline"}</p>
      {data.policy_lifecycle.events.length?<table><thead><tr><th>Time</th><th>Action</th><th>Version</th></tr></thead><tbody>{data.policy_lifecycle.events.map((event,index)=><tr key={index}><td>{event.timestamp}</td><td>{event.action}</td><td>{event.version}</td></tr>)}</tbody></table>:<p>No candidate activation events observed in this process.</p>}
    </Panel>
    <Panel title="Measured development comparisons" subtitle="Separate from live telemetry. Repeated development probes are not held-out security evidence.">
      {experiments.length ? <table><thead><tr><th>Mode</th><th>Concurrency</th><th>Attack recall</th><th>Macro F1</th><th>Benign FPR</th><th>p95 latency</th><th>Completed/s</th><th>Fully inspected/s</th></tr></thead><tbody>{experiments.map((run)=><tr key={`${run.mode}-${run.concurrency}`}>
        <td>{run.mode}</td><td>{run.concurrency}</td><td>{run.metrics.attack_detection_recall_all_submitted===null?"—":`${((run.metrics.attack_detection_recall_all_submitted??0)*100).toFixed(1)}%`}</td>
        <td>{run.metrics.macro_f1?.toFixed(3)??"—"}</td><td>{run.metrics.benign_false_positive_rate_all_submitted===null?"—":`${((run.metrics.benign_false_positive_rate_all_submitted??0)*100).toFixed(1)}%`}</td>
        <td>{milliseconds(run.metrics.latency_p95_ms)}</td><td>{run.metrics.completed_rps?.toFixed(2)??"—"}</td><td>{run.metrics.fully_inspected_rps?.toFixed(2)??"—"}</td>
      </tr>)}</tbody></table>:<p>No measured run is selected on the backend.</p>}
    </Panel>
  </div>;
}
