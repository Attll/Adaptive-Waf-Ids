"""Render only observed development measurements; refuse to overwrite existing figures."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway",type=Path,required=True)
    parser.add_argument("--threads",type=Path,required=True)
    parser.add_argument("--devices",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("new figure directory required")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    report=json.loads(args.gateway.read_text(encoding="utf-8"))
    experiments=report["experiments"]
    if not report.get("transport_encoding_shared_across_modes"):
        parser.error("matched transport representations required")
    args.output.mkdir(parents=True)
    plt.rcParams.update({"font.size":9,"axes.spines.top":False,"axes.spines.right":False})
    def save(fig,name):
        fig.savefig(args.output/(name+".png"),dpi=180,bbox_inches="tight")
        fig.savefig(args.output/(name+".pdf"),bbox_inches="tight")
        plt.close(fig)
    groups=sorted({run["concurrency"] for run in experiments})
    fig,axes=plt.subplots(1,2,figsize=(12,5))
    for concurrency in groups:
        runs=[run for run in experiments if run["concurrency"]==concurrency]
        labels=[r["mode"].replace("_"," ") for r in runs]
        axes[0].plot(labels,[r["metrics"]["latency_p95_ms"] for r in runs],"o-",label=f"Concurrency {concurrency}")
        axes[1].plot(labels,[r["metrics"]["completed_rps"] for r in runs],"o-",label=f"Completed, c={concurrency}")
        axes[1].plot(labels,[r["metrics"]["fully_inspected_rps"] for r in runs],"x--",label=f"Fully inspected, c={concurrency}")
    for axis in axes:
        axis.tick_params(axis="x",rotation=60)
        axis.legend(fontsize=8,loc="upper left",bbox_to_anchor=(0,1.18),ncol=2)
    axes[0].set_ylabel("Client p95 (ms)")
    axes[1].set_ylabel("Requests / second")
    fig.suptitle("Six repeated development probes · diagnostic workload · no throughput capacity claim",y=1.12)
    save(fig,"latency_throughput")
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    runs=[r for r in experiments if r["concurrency"]==1 and r["mode"].endswith("gateway")]
    for index,run in enumerate(runs):
        metrics=run["metrics"]
        axes[0].scatter(metrics["cpu_core_seconds"]*1000/metrics["request_count"],metrics["attack_detection_recall_all_submitted"],label=run["mode"])
        axes[1].scatter(metrics["benign_false_positive_rate_all_submitted"],metrics["attack_detection_recall_all_submitted"],marker=["o","s","^","x"][index%4],s=70,label=run["mode"])
    axes[0].set_xlabel("Process-group CPU ms / submitted request")
    axes[1].set_xlabel("Observed benign FPR (2 repeated benign requests)")
    for axis in axes:
        axis.set_ylabel("Observed attack recall (5 attacks repeated twice)")
        axis.set_ylim(-.05,1.1)
    axes[0].legend(fontsize=8)
    axes[1].set_xlim(-.02,.1)
    fig.suptitle("Development operating points · overlapping points · no ROC or security interval inferred")
    save(fig,"development_cost_recall_fpr")
    fig,axis=plt.subplots(figsize=(8,4))
    for run in runs:
        rows=run["records"]
        if not any(row.get("predicted_attack") is not None for row in rows):
            continue
        accuracy=sum(row.get("predicted_attack")==row["expected"] for row in rows)/len(rows)
        axis.scatter(run["metrics"]["cpu_core_seconds"]*1000/len(rows),accuracy,label=run["mode"])
    axis.set_xlabel("Process-group CPU ms / submitted request")
    axis.set_ylabel("Exact-class development accuracy")
    axis.set_title("Six repeated development probes · c=1 · no held-out claim")
    axis.set_ylim(-.05,1.1)
    axis.legend(fontsize=7,loc='center left',bbox_to_anchor=(1,0.5))
    save(fig,"cost_accuracy")
    threads=json.loads(args.threads.read_text(encoding="utf-8"))["summary"]
    fig,axis=plt.subplots(figsize=(6,3))
    axis.bar(["Original all-core" if r["threads"] is None else str(r["threads"])+" thread(s)" for r in threads],[r["p95_ms"] for r in threads])
    axis.set_ylabel("Warmed pipeline p95 (ms)")
    axis.set_title("Inference thread diagnostic · predictions and risks checked equivalent")
    save(fig,"thread_profile")
    runs=[run for run in experiments if run["concurrency"]==1 and run["mode"].endswith("gateway")]
    stages=["semantic_rules","triage","router","injection_expert","execution_expert","deep"]
    fig,axis=plt.subplots(figsize=(12,5))
    import numpy as np
    positions=np.arange(len(runs))
    for index,stage in enumerate(stages):
        counts=[sum(stage in (row.get("stages_ms") or {}) for row in run["records"]) for run in runs]
        axis.bar(positions+(index-2.5)*.12,counts,width=.12,label=stage)
    axis.set_xticks(positions,[run["mode"].replace('_',' ') for run in runs],rotation=60,ha='right')
    axis.set_ylabel("Observed stage executions / 12 submitted requests")
    axis.set_title("Journal-derived invocation counts · c=1 · semantic guard hits bypass optional models")
    axis.legend(fontsize=8,loc='center left',bbox_to_anchor=(1,.5))
    save(fig,"model_invocations")
    if args.devices:
        devices=json.loads(args.devices.read_text(encoding="utf-8"))["summary"]
        fig,axis=plt.subplots(figsize=(6,3))
        axis.bar([r["device"] for r in devices],[r["p95_ms"] for r in devices])
        axis.set_ylabel("Warmed deep-model p95 (ms)")
        axis.set_title("Existing deep model · tokenization, transfer and inference · one CPU thread")
        save(fig,"deep_device_profile")
    inputs=[args.gateway,args.threads]+([args.devices] if args.devices else [])
    (args.output/"sources.json").write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},indent=2))
    print(args.output)


if __name__=="__main__":
    main()
