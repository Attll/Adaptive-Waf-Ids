import { Fragment, useMemo } from "react";
import type { DetectionEvidence, EventRecord } from "../api";
import { colorFor, label as humanize, milliseconds, percent } from "../lib/format";
import { EmptyState, Icon } from "./Ui";

export type FlowNode = {
  key: string;
  title: string;
  verdict: string;
  tone: string;
  latencyMs?: number;
  confidence?: number;
  model?: string;
  facts: [string, string][];
  skipped?: boolean;
};

/**
 * Reconstructs the journey of one request: which stages ran, what each decided, how long it took, and what the
 * gateway did with the answer. Stages the pipeline skipped are shown dimmed so the adaptive path stays visible.
 */
export function buildFlow(event: EventRecord | undefined, detection: DetectionEvidence | undefined): FlowNode[] {
  if (!event) return [];
  const nodes: FlowNode[] = [];
  const latency = detection?.latency_by_stage_ms ?? {};

  nodes.push({
    key: "ingress",
    title: "Gateway ingress",
    verdict: `${event.method ?? "?"} ${event.path ?? "/"}`,
    tone: "#6e6e6e",
    latencyMs: undefined,
    facts: [
      ["Source", event.sourceIp ?? "not recorded"],
      ["Mode", humanize(event.mode ?? "NORMAL")],
      ["Request", (event.requestId ?? "—").slice(0, 8)]
    ]
  });

  if (detection) {
    nodes.push({
      key: "features",
      title: "Feature extraction",
      verdict: "Canonicalised",
      tone: "#6366f1",
      latencyMs: latency.feature_extraction,
      facts: [["Representation", "http-classical-v1"]]
    });

    nodes.push({
      key: "triage",
      title: "Triage",
      verdict: humanize(detection.triage.decision),
      tone: colorFor("TRIAGE"),
      latencyMs: latency.triage,
      confidence: detection.triage.suspicious_probability,
      model: detection.model_versions.triage,
      facts: [
        ["Suspicious", percent(detection.triage.suspicious_probability, 2)],
        ["Model", detection.model_versions.triage ?? "—"]
      ]
    });

    const routerRan = Boolean(detection.router);
    nodes.push({
      key: "router",
      title: "Router",
      verdict: routerRan ? detection.router!.selected_experts.map(humanize).join(" + ") : "Not reached",
      tone: colorFor("ROUTER"),
      latencyMs: latency.router,
      skipped: !routerRan,
      model: detection.model_versions.router,
      facts: routerRan
        ? Object.entries(detection.router!.scores).map(([family, score]) => [humanize(family), percent(score, 1)] as [string, string])
        : [["Reason", "Triage exited early"]]
    });

    const families = ["INJECTION", "EXECUTION"];
    families.forEach((family) => {
      const output = detection.expert_outputs.find((entry) => (entry.model_version ?? "").length >= 0 && belongsTo(entry, family, detection));
      const ran = Boolean(output);
      nodes.push({
        key: `expert-${family}`,
        title: `${humanize(family)} expert`,
        verdict: ran ? humanize(output!.predicted_attack) : "Not selected",
        tone: colorFor(family),
        latencyMs: latency[`${family.toLowerCase()}_expert`],
        confidence: output?.confidence,
        skipped: !ran,
        model: output?.model_version,
        facts: ran
          ? [
              ["Confidence", percent(output!.confidence, 2)],
              ["Risk", percent(output!.risk, 2)],
              ["Model", output!.model_version ?? "—"]
            ]
          : [["Reason", routerRan ? "Router did not select this family" : "Router did not run"]]
      });
    });

    nodes.push({
      key: "deep",
      title: "Deep escalation",
      verdict: detection.deep_output ? humanize(detection.deep_output.predicted_attack) : "Not escalated",
      tone: colorFor("DEEP"),
      latencyMs: latency.deep,
      confidence: detection.deep_output?.confidence,
      skipped: !detection.deep_output,
      model: detection.deep_output?.model_version ?? detection.model_versions.deep,
      facts: detection.deep_output
        ? [
            ["Confidence", percent(detection.deep_output.confidence, 2)],
            ["Risk", percent(detection.deep_output.risk, 2)],
            ["Model", detection.deep_output.model_version ?? "—"]
          ]
        : [["Reason", "Expert confidence cleared the escalation threshold"]]
    });

    nodes.push({
      key: "fusion",
      title: "Risk fusion",
      verdict: percent(detection.risks.overall, 2),
      tone: "#a855f7",
      facts: [
        ["HTTP", percent(detection.risks.http, 1)],
        ["Behaviour", percent(detection.risks.behaviour, 1)],
        ["Network", percent(detection.risks.network, 1)]
      ]
    });
  }

  const blocked = event.action === "BLOCK" || event.action === "RATE_LIMIT" || event.action === "TEMPORARY_BLOCK";
  nodes.push({
    key: "policy",
    title: "Policy enforcement",
    verdict: humanize(event.action ?? "UNKNOWN"),
    tone: blocked ? "#ff5c5c" : "#2bd576",
    facts: [
      ["Classification", humanize(event.predictedAttack ?? "UNKNOWN")],
      ["Overall risk", percent(event.risk, 2)],
      ["HTTP status", String(event.statusCode)]
    ]
  });

  nodes.push({
    key: "upstream",
    title: blocked ? "Upstream (not reached)" : "Demo upstream",
    verdict: blocked ? "Request never proxied" : event.upstream ?? "Proxied",
    tone: blocked ? "#4a4a4a" : "#22d3ee",
    latencyMs: blocked ? undefined : event.upstreamLatencyMs,
    skipped: blocked,
    facts: blocked
      ? [["Mitigation", humanize(event.mitigation ?? "BLOCKED_AT_GATEWAY")]]
      : [
          ["Round trip", milliseconds(event.upstreamLatencyMs)],
          ["Status", String(event.statusCode)]
        ]
  });

  return nodes;
}

/** The pipeline reports expert outputs positionally; match them back to their family through the model version. */
function belongsTo(output: DetectionEvidence["expert_outputs"][number], family: string, detection: DetectionEvidence): boolean {
  const version = detection.model_versions[family.toLowerCase()];
  if (version && output.model_version === version) return true;
  const selected = detection.router?.selected_experts ?? [];
  if (selected.length === 1) return selected[0].toUpperCase() === family;
  return false;
}

export function RequestFlow({ nodes }: { nodes: FlowNode[] }) {
  const totalLatency = useMemo(() => nodes.reduce((sum, node) => sum + (node.latencyMs ?? 0), 0), [nodes]);
  if (!nodes.length) {
    return <EmptyState title="No request selected" detail="Choose a request from the log to replay its path through the pipeline." icon={<Icon name="flow" />} />;
  }
  const slowest = Math.max(1, ...nodes.map((node) => node.latencyMs ?? 0));

  return (
    <div className="flow">
      {nodes.map((node, index) => (
        <Fragment key={node.key}>
          {index > 0 && (
            <div className="flow-link">
              {node.latencyMs !== undefined && node.latencyMs > 0 && (
                <span className="flow-latency">{node.latencyMs.toFixed(1)}ms</span>
              )}
              <svg width="46" height="22" viewBox="0 0 46 22">
                <path className="flow-path" d="M2 11h42" />
                {!node.skipped && <path className="flow-pulse" d="M2 11h42" style={{ stroke: node.tone }} />}
                <path className="flow-path" d="M38 6l6 5-6 5" />
              </svg>
            </div>
          )}
          <article
            className={`flow-node${node.skipped ? " skipped" : " active"}`}
            style={{ ["--node-tone" as string]: node.tone, animationDelay: `${index * 0.055}s` }}
          >
            <header>
              <span className="idx">{index + 1}</span>
              <h4>{node.title}</h4>
            </header>
            <p className="verdict" style={{ color: node.skipped ? "var(--text-muted)" : node.tone }}>{node.verdict}</p>
            <div className="meta">
              {node.facts.map(([key, value]) => (
                <span key={key}>{key}: {value}</span>
              ))}
            </div>
            {node.latencyMs !== undefined && node.latencyMs > 0 && (
              <div className="bar" title={`${node.latencyMs.toFixed(3)} ms of ${totalLatency.toFixed(1)} ms`}>
                <i style={{ width: `${Math.max(3, (node.latencyMs / slowest) * 100)}%` }} />
              </div>
            )}
          </article>
        </Fragment>
      ))}
    </div>
  );
}
