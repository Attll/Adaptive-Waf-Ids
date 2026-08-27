import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  corpusSummary,
  deployNetworkFlow,
  probeGateway,
  sampleHttpCorpus,
  sampleNetworkCorpus,
  type CorpusSummary,
  type GatewayProbeResult,
  type HttpCorpusRecord,
  type Infrastructure,
  type NetworkCorpusRecord
} from "../api";
import { DonutChart, RankedBars, Sparkline } from "../components/Charts";
import { Badge, EmptyState, Icon, KV, Metric, Panel, Segmented, Slider, Switch } from "../components/Ui";
import { colorFor, compactNumber, label as humanize, milliseconds, percent, relativeTime, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

type Plane = "http" | "network";

type HttpOutcome = GatewayProbeResult & { expected: string };
type NetworkOutcome = {
  sourceIp: string;
  expected: string;
  classified?: string;
  risk?: number;
  confidence?: number;
  latencyMs: number;
  ok: boolean;
  error?: string;
};

/** Synthetic origins so generated traffic is attributable to a source the console can map and block. */
const SOURCE_POOL = ["203.0.113.10", "203.0.113.88", "198.51.100.7", "192.0.2.44", "192.0.2.201", "10.12.0.5"];
const DESTINATION = "10.0.0.20";

export function Generator(props: ViewProps) {
  const [plane, setPlane] = useState<Plane>("http");
  const [corpus, setCorpus] = useState<CorpusSummary>();
  const [corpusError, setCorpusError] = useState<string>();

  useEffect(() => {
    corpusSummary()
      .then(setCorpus)
      .catch((error) => setCorpusError(error instanceof Error ? error.message : "corpus unavailable"));
  }, []);

  return (
    <div className="stack">
      <div className="toolbar">
        <Segmented<Plane>
          value={plane}
          onChange={setPlane}
          options={[
            { value: "http", label: "HTTP payloads" },
            { value: "network", label: "Network flows" }
          ]}
        />
        {corpus && (
          <span className="toolbar-count">
            {corpus.http.records} HTTP records · {corpus.network.records} flow records sampled from the training datasets
          </span>
        )}
      </div>

      {corpusError && (
        <Panel title="Payload corpus unavailable">
          <EmptyState
            title="No sampled corpus is present"
            detail={`${corpusError}. Run scripts/build_probe_corpus.py to sample the processed datasets, then restart the detection service.`}
            icon={<Icon name="inbox" />}
          />
        </Panel>
      )}

      {plane === "http" ? <HttpGenerator {...props} corpus={corpus} /> : <NetworkGenerator {...props} corpus={corpus} />}

      <InfrastructurePanel {...props} />
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * HTTP payload generator
 * ------------------------------------------------------------------ */
function HttpGenerator({ notify, refresh, corpus }: ViewProps & { corpus?: CorpusSummary }) {
  const available = useMemo(() => Object.keys(corpus?.http.labels ?? {}), [corpus]);
  const [selected, setSelected] = useState<string[]>([]);
  const [count, setCount] = useState(24);
  const [delayMs, setDelayMs] = useState(120);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [outcomes, setOutcomes] = useState<HttpOutcome[]>([]);
  const [preview, setPreview] = useState<HttpCorpusRecord[]>();
  const cancelled = useRef(false);

  useEffect(() => {
    if (available.length && !selected.length) setSelected(available);
  }, [available, selected.length]);

  const toggle = (name: string) =>
    setSelected((current) => (current.includes(name) ? current.filter((entry) => entry !== name) : [...current, name]));

  const loadPreview = async () => {
    try {
      const { samples } = await sampleHttpCorpus(8, selected);
      setPreview(samples);
    } catch (error) {
      notify("Sampling failed", error instanceof Error ? error.message : "corpus unavailable", "danger");
    }
  };

  const run = async () => {
    setRunning(true);
    cancelled.current = false;
    setOutcomes([]);
    setProgress(0);
    try {
      const { samples } = await sampleHttpCorpus(count, selected);
      if (!samples.length) {
        notify("Nothing to send", "The selected classes are not present in the corpus.", "warning");
        return;
      }
      const collected: HttpOutcome[] = [];
      for (let index = 0; index < samples.length; index += 1) {
        if (cancelled.current) break;
        const record = samples[index];
        const result = await probeGateway({
          label: `${record.label} ${record.path}`,
          method: record.method,
          path: record.path,
          query: record.query,
          body: record.body,
          expected: record.label
        });
        collected.push({ ...result, expected: record.label });
        setOutcomes([...collected].reverse());
        setProgress(index + 1);
        if (delayMs > 0 && index < samples.length - 1) {
          await new Promise((resolve) => window.setTimeout(resolve, delayMs));
        }
      }
      notify(
        cancelled.current ? "Generation stopped" : "Generation complete",
        `${collected.filter((entry) => entry.blocked).length} of ${collected.length} mitigated at the gateway`
      );
      await refresh();
    } catch (error) {
      notify("Generation failed", error instanceof Error ? error.message : "unknown error", "danger");
    } finally {
      setRunning(false);
    }
  };

  const blocked = outcomes.filter((entry) => entry.blocked).length;
  const forwarded = outcomes.filter((entry) => !entry.blocked && !entry.error).length;
  const failed = outcomes.filter((entry) => entry.error).length;
  const attackOutcomes = outcomes.filter((entry) => entry.expected !== "BENIGN");
  const caught = attackOutcomes.filter((entry) => entry.blocked).length;
  const benignOutcomes = outcomes.filter((entry) => entry.expected === "BENIGN");
  const falsePositives = benignOutcomes.filter((entry) => entry.blocked).length;
  const meanRoundTrip = outcomes.length ? outcomes.reduce((sum, entry) => sum + entry.roundTripMs, 0) / outcomes.length : 0;

  return (
    <div className="stack">
      <Panel
        title="Generate HTTP traffic from the dataset"
        subtitle="Randomised records from the processed ATRDF split are replayed through the gateway to the demo upstream"
        action={running ? <Badge value={`${progress}/${count}`} tone="info" /> : undefined}
      >
        <div className="chip-row" style={{ marginBottom: 16 }}>
          {available.map((name) => {
            const active = selected.includes(name);
            return (
              <button
                key={name}
                className="chip"
                onClick={() => toggle(name)}
                disabled={running}
                style={{
                  borderColor: active ? colorFor(name) : undefined,
                  background: active ? "rgba(255,255,255,0.04)" : undefined,
                  color: active ? "var(--text)" : undefined
                }}
              >
                <i className="dot" style={{ background: active ? colorFor(name) : "var(--text-faint)" }} />
                {humanize(name)} <strong>{corpus?.http.labels[name] ?? 0}</strong>
              </button>
            );
          })}
          {!available.length && <span className="muted">No HTTP corpus is loaded.</span>}
        </div>

        <div className="grid-2" style={{ gap: 20 }}>
          <Slider label="Requests to send" value={count} min={1} max={200} step={1} format={(value) => `${value} requests`} onChange={setCount} />
          <Slider label="Delay between requests" value={delayMs} min={0} max={1000} step={20} format={(value) => (value ? `${value} ms` : "no delay")} onChange={setDelayMs} />
        </div>

        <div className="btn-row" style={{ marginTop: 16 }}>
          <button className="btn primary" onClick={() => void run()} disabled={running || !selected.length}>
            {running ? <span className="spinner" /> : <Icon name="send" size={13} />}
            {running ? `Sending ${progress}/${count}` : "Send through the gateway"}
          </button>
          <button className="btn danger" onClick={() => { cancelled.current = true; }} disabled={!running}>Stop</button>
          <button className="btn ghost" onClick={() => void loadPreview()} disabled={running}>Preview sample</button>
          <button className="btn ghost" onClick={() => setSelected(available)} disabled={running}>All classes</button>
        </div>
      </Panel>

      {preview && (
        <Panel title="Sampled payloads" subtitle="A fresh random draw from the corpus, exactly as it would be sent" flush>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Class</th><th>Method</th><th>Path</th><th>Query</th></tr></thead>
              <tbody>
                {preview.map((record, index) => (
                  <tr key={index}>
                    <td><span className="chip"><i className="dot" style={{ background: colorFor(record.label) }} />{humanize(record.label)}</span></td>
                    <td className="mono">{record.method}</td>
                    <td className="mono muted">{record.path}</td>
                    <td className="mono faint" style={{ fontSize: 10.5, maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis" }}>{record.query || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {outcomes.length > 0 && (
        <>
          <div className="grid-4 stagger">
            <Metric label="Sent" value={outcomes.length} detail={`${failed} failed to reach the gateway`} tone="info" icon={<Icon name="send" size={13} />} />
            <Metric label="Mitigated" value={blocked} detail={`${forwarded} forwarded to the upstream`} tone="danger" icon={<Icon name="shield" size={13} />} />
            <Metric label="Attack recall" value={attackOutcomes.length ? percent(caught / attackOutcomes.length, 1) : "—"} detail={`${caught} of ${attackOutcomes.length} labelled attacks blocked`} tone="success" icon={<Icon name="target" size={13} />} />
            <Metric label="False positives" value={falsePositives} detail={`of ${benignOutcomes.length} benign requests · mean ${milliseconds(meanRoundTrip, 1)}`} tone={falsePositives ? "warning" : "success"} icon={<Icon name="alert" size={13} />} />
          </div>

          <div className="grid-2">
            <Panel title="Outcome by labelled class" subtitle="How the gateway treated each class of generated traffic">
              <RankedBars
                data={classRecall(outcomes)}
                format={(value) => percent(value, 0)}
                colorKey={(name) => colorFor(name)}
              />
            </Panel>
            <Panel title="Response status returned">
              <DonutChart
                data={sortedEntries(outcomes.reduce<Record<string, number>>((result, entry) => {
                  const key = entry.error ? "error" : String(entry.status);
                  result[key] = (result[key] ?? 0) + 1;
                  return result;
                }, {})).map(([name, value]) => ({ label: name, value }))}
                centerLabel="responses"
                size={140}
              />
            </Panel>
          </div>

          <Panel title="Generated requests" subtitle="Newest first; each one is journalled and appears in Live Attacks" flush>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Labelled class</th><th>Method</th><th>Target</th><th>Status</th><th>Gateway outcome</th><th>Classified</th><th>Round trip</th></tr></thead>
                <tbody>
                  {outcomes.slice(0, 60).map((entry, index) => (
                    <tr key={index}>
                      <td><span className="chip"><i className="dot" style={{ background: colorFor(entry.expected) }} />{humanize(entry.expected)}</span></td>
                      <td className="mono">{entry.method}</td>
                      <td className="mono muted" style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis" }}>{entry.target}</td>
                      <td className="mono">{entry.status || "—"}</td>
                      <td>
                        {entry.error
                          ? <Badge value="ERROR" tone="danger" />
                          : <Badge value={entry.blocked ? "MITIGATED" : "FORWARDED"} tone={entry.blocked ? "danger" : "success"} />}
                      </td>
                      <td>{entry.predictedAttack ? humanize(entry.predictedAttack) : "—"}</td>
                      <td className="mono muted">{milliseconds(entry.roundTripMs, 1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Network flow generator
 * ------------------------------------------------------------------ */
function NetworkGenerator({ notify, corpus }: ViewProps & { corpus?: CorpusSummary }) {
  const available = useMemo(() => Object.keys(corpus?.network.labels ?? {}), [corpus]);
  const [selected, setSelected] = useState<string[]>([]);
  const [count, setCount] = useState(20);
  const [delayMs, setDelayMs] = useState(150);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [outcomes, setOutcomes] = useState<NetworkOutcome[]>([]);
  const [preview, setPreview] = useState<NetworkCorpusRecord[]>();
  const cancelled = useRef(false);

  useEffect(() => {
    if (available.length && !selected.length) setSelected(available);
  }, [available, selected.length]);

  const toggle = (name: string) =>
    setSelected((current) => (current.includes(name) ? current.filter((entry) => entry !== name) : [...current, name]));

  const run = async () => {
    setRunning(true);
    cancelled.current = false;
    setOutcomes([]);
    setProgress(0);
    try {
      const { samples } = await sampleNetworkCorpus(count, selected);
      if (!samples.length) {
        notify("Nothing to send", "The selected classes are not present in the flow corpus.", "warning");
        return;
      }
      const collected: NetworkOutcome[] = [];
      for (let index = 0; index < samples.length; index += 1) {
        if (cancelled.current) break;
        const record = samples[index];
        const sourceIp = SOURCE_POOL[index % SOURCE_POOL.length];
        const result = await deployNetworkFlow(sourceIp, DESTINATION, record.features);
        collected.push({
          sourceIp,
          expected: record.label,
          classified: result.networkClass,
          risk: result.risk,
          confidence: result.confidence,
          latencyMs: result.latencyMs,
          ok: result.ok,
          error: result.error
        });
        setOutcomes([...collected].reverse());
        setProgress(index + 1);
        if (delayMs > 0 && index < samples.length - 1) {
          await new Promise((resolve) => window.setTimeout(resolve, delayMs));
        }
      }
      notify(
        cancelled.current ? "Flow replay stopped" : "Flow replay complete",
        `${collected.filter((entry) => entry.ok).length} of ${collected.length} classified and written to Redis`
      );
    } catch (error) {
      notify("Flow replay failed", error instanceof Error ? error.message : "unknown error", "danger");
    } finally {
      setRunning(false);
    }
  };

  const succeeded = outcomes.filter((entry) => entry.ok);
  const matched = succeeded.filter((entry) => entry.classified === entry.expected).length;
  const meanRisk = succeeded.length ? succeeded.reduce((sum, entry) => sum + (entry.risk ?? 0), 0) / succeeded.length : 0;
  const meanLatency = outcomes.length ? outcomes.reduce((sum, entry) => sum + entry.latencyMs, 0) / outcomes.length : 0;

  return (
    <div className="stack">
      <Panel
        title="Replay network flows into the sensor"
        subtitle="Randomised CICIDS flow records are classified by the sensor, which writes the resulting risk context into Redis for the gateway to read"
        action={running ? <Badge value={`${progress}/${count}`} tone="info" /> : undefined}
      >
        <div className="chip-row" style={{ marginBottom: 16 }}>
          {available.map((name) => {
            const active = selected.includes(name);
            return (
              <button
                key={name}
                className="chip"
                onClick={() => toggle(name)}
                disabled={running}
                style={{
                  borderColor: active ? colorFor(name) : undefined,
                  background: active ? "rgba(255,255,255,0.04)" : undefined,
                  color: active ? "var(--text)" : undefined
                }}
              >
                <i className="dot" style={{ background: active ? colorFor(name) : "var(--text-faint)" }} />
                {humanize(name)} <strong>{corpus?.network.labels[name] ?? 0}</strong>
              </button>
            );
          })}
          {!available.length && <span className="muted">No network corpus is loaded.</span>}
        </div>

        <div className="grid-2" style={{ gap: 20 }}>
          <Slider label="Flows to replay" value={count} min={1} max={160} step={1} format={(value) => `${value} flows`} onChange={setCount} />
          <Slider label="Delay between flows" value={delayMs} min={0} max={1000} step={20} format={(value) => (value ? `${value} ms` : "no delay")} onChange={setDelayMs} />
        </div>

        <div className="btn-row" style={{ marginTop: 16 }}>
          <button className="btn primary" onClick={() => void run()} disabled={running || !selected.length}>
            {running ? <span className="spinner" /> : <Icon name="network" size={13} />}
            {running ? `Replaying ${progress}/${count}` : "Replay into the sensor"}
          </button>
          <button className="btn danger" onClick={() => { cancelled.current = true; }} disabled={!running}>Stop</button>
          <button
            className="btn ghost"
            disabled={running}
            onClick={() => void sampleNetworkCorpus(6, selected).then(({ samples }) => setPreview(samples)).catch(() => setPreview([]))}
          >
            Preview sample
          </button>
        </div>
      </Panel>

      {preview && preview.length > 0 && (
        <Panel title="Sampled flows" subtitle="A fresh random draw; every value is a real feature from the processed CICIDS split" flush>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Class</th><th>Destination port</th><th>Protocol</th><th>Duration</th><th>Fwd packets</th><th>Bwd packets</th><th>Bytes/s</th></tr></thead>
              <tbody>
                {preview.map((record, index) => (
                  <tr key={index}>
                    <td><span className="chip"><i className="dot" style={{ background: colorFor(record.label) }} />{humanize(record.label)}</span></td>
                    <td className="mono">{record.features["Dst Port"] ?? "—"}</td>
                    <td className="mono">{record.features["Protocol"] ?? "—"}</td>
                    <td className="mono muted">{compactNumber(record.features["Flow Duration"] ?? 0)} µs</td>
                    <td className="mono muted">{record.features["Tot Fwd Pkts"] ?? "—"}</td>
                    <td className="mono muted">{record.features["Tot Bwd Pkts"] ?? "—"}</td>
                    <td className="mono muted">{compactNumber(record.features["Flow Byts/s"] ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {outcomes.length > 0 && (
        <>
          <div className="grid-4 stagger">
            <Metric label="Flows replayed" value={outcomes.length} detail={`${outcomes.length - succeeded.length} rejected by the sensor`} tone="info" icon={<Icon name="network" size={13} />} />
            <Metric label="Classification match" value={succeeded.length ? percent(matched / succeeded.length, 1) : "—"} detail={`${matched} agreed with the dataset label`} tone="success" icon={<Icon name="check" size={13} />} />
            <Metric label="Mean network risk" value={percent(meanRisk, 1)} detail="Written to Redis as gateway context" tone="warning" icon={<Icon name="target" size={13} />} />
            <Metric label="Mean sensor latency" value={milliseconds(meanLatency, 1)} detail="Measured in the browser" tone="violet" icon={<Icon name="clock" size={13} />} />
          </div>

          <Panel title="Classified flows" subtitle="Each row also wrote a waf:network key that the gateway reads per request" flush>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Source</th><th>Dataset label</th><th>Sensor classification</th><th>Agreement</th><th>Risk</th><th>Confidence</th><th>Latency</th></tr></thead>
                <tbody>
                  {outcomes.slice(0, 60).map((entry, index) => (
                    <tr key={index}>
                      <td className="mono cell-strong">{entry.sourceIp}</td>
                      <td><span className="chip"><i className="dot" style={{ background: colorFor(entry.expected) }} />{humanize(entry.expected)}</span></td>
                      <td>{entry.classified ? humanize(entry.classified) : <span className="muted">{entry.error ?? "—"}</span>}</td>
                      <td>
                        {entry.ok
                          ? <Badge value={entry.classified === entry.expected ? "MATCH" : "DIFFERS"} tone={entry.classified === entry.expected ? "success" : "warning"} />
                          : <Badge value="FAILED" tone="danger" />}
                      </td>
                      <td className="mono">{entry.risk === undefined ? "—" : percent(entry.risk, 1)}</td>
                      <td className="mono muted">{entry.confidence === undefined ? "—" : percent(entry.confidence, 1)}</td>
                      <td className="mono muted">{milliseconds(entry.latencyMs, 1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Live Redis and database panel
 * ------------------------------------------------------------------ */
export function InfrastructurePanel({ api }: ViewProps) {
  const [state, setState] = useState<Infrastructure>();
  const [error, setError] = useState<string>();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [history, setHistory] = useState<number[]>([]);

  const load = useCallback(async () => {
    try {
      const next = await api.infrastructure();
      setState(next);
      setError(undefined);
      setHistory((current) => [...current, next.redis.totalTrackedKeys ?? 0].slice(-40));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "infrastructure status unavailable");
    }
  }, [api]);

  useEffect(() => {
    void load();
    if (!autoRefresh) return;
    const timer = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(timer);
  }, [load, autoRefresh]);

  if (error) {
    return (
      <Panel title="Redis and database" action={<Badge value="UNAVAILABLE" tone="danger" />}>
        <EmptyState title="Infrastructure status unavailable" detail={error} icon={<Icon name="health" />} />
      </Panel>
    );
  }
  if (!state) {
    return <Panel title="Redis and database"><EmptyState title="Reading store status" detail="Querying Redis and Postgres." icon={<Icon name="health" />} /></Panel>;
  }

  const redis = state.redis;
  const database = state.database;
  const namespaces = Object.entries(redis.namespaces ?? {});

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric
          label="Redis"
          value={redis.reachable ? "Connected" : "Unreachable"}
          detail={redis.reachable ? `${redis.ping} in ${milliseconds(redis.pingLatencyMs, 2)}` : redis.error ?? "no connection"}
          tone={redis.reachable ? "success" : "danger"}
          icon={<Icon name="bolt" size={13} />}
          spark={history}
        />
        <Metric
          label="Tracked keys"
          value={redis.totalTrackedKeys ?? 0}
          detail="Behaviour, blocks, network context, and load shedding"
          tone="info"
          icon={<Icon name="layers" size={13} />}
          spark={history}
        />
        <Metric
          label="Journalled requests"
          value={database.totalEvents ?? 0}
          detail={database.newestEventAt ? `newest ${relativeTime(database.newestEventAt)}` : "no events yet"}
          tone={database.reachable ? "violet" : "danger"}
          icon={<Icon name="audit" size={13} />}
        />
        <Metric
          label="Postgres"
          value={database.reachable ? "Connected" : "Unreachable"}
          detail={database.reachable ? `query in ${milliseconds(database.queryLatencyMs, 2)}` : database.error ?? "no connection"}
          tone={database.reachable ? "success" : "danger"}
          icon={<Icon name="health" size={13} />}
        />
      </div>

      <div className="grid-2">
        <Panel
          title="Redis activity"
          subtitle="Live key counts; generate traffic and watch these move"
          action={
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11.5, color: "var(--text-secondary)" }}>
              <Switch checked={autoRefresh} onChange={setAutoRefresh} label="Auto refresh" />
              2s refresh
            </label>
          }
        >
          {namespaces.length ? (
            <>
              <RankedBars
                data={namespaces.map(([name, namespace]) => ({ label: name, value: namespace.count }))}
                colorKey={(name) => colorFor(name)}
              />
              <div style={{ marginTop: 16 }}>
                <Sparkline values={history.length > 1 ? history : [0, 0]} color="#2bd576" height={38} />
                <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>Total tracked keys over the last {history.length} samples</p>
              </div>
            </>
          ) : (
            <EmptyState title="No keys tracked yet" detail="Redis is reachable but holds no WAF keys. Generate traffic to populate behavioural counters." icon={<Icon name="bolt" />} />
          )}
        </Panel>

        <Panel title="Database" subtitle="Connect an external client to inspect the journal directly">
          <dl className="kv-list">
            <KV k="Connect from your machine" v={<span className="mono" style={{ fontSize: 11 }}>{database.externalJdbcUrl ?? "—"}</span>} />
            <KV k="Username" v={<span className="mono">{database.username ?? "—"}</span>} />
            <KV k="Service connection" v={<span className="mono faint" style={{ fontSize: 10.5 }}>{database.jdbcUrl ?? "—"}</span>} />
            <KV k="Journalled events" v={String(database.totalEvents ?? 0)} />
            <KV k="Escalation records" v={String(database.escalationRecords ?? 0)} />
            <KV k="Newest event" v={database.newestEventAt ? `${relativeTime(database.newestEventAt)} (${database.secondsSinceNewestEvent}s)` : "none"} />
          </dl>
          {database.tableCounts && (
            <div style={{ marginTop: 14 }}>
              <RankedBars
                data={Object.entries(database.tableCounts).map(([name, value]) => ({ label: name, value: Math.max(0, value) }))}
                colorKey={() => "#3b82f6"}
              />
            </div>
          )}
        </Panel>
      </div>

      {namespaces.some(([, namespace]) => namespace.sample.length > 0) && (
        <Panel title="Redis keys" subtitle="A live sample of the actual keys the platform is writing" flush>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Namespace</th><th>Key</th><th>Type</th><th>Expires in</th></tr></thead>
              <tbody>
                {namespaces.flatMap(([name, namespace]) =>
                  namespace.sample.map((entry) => (
                    <tr key={entry.key}>
                      <td><span className="chip"><i className="dot" style={{ background: colorFor(name) }} />{name}</span></td>
                      <td className="mono">{entry.key}</td>
                      <td className="mono muted">{entry.type}</td>
                      <td className="mono muted">{entry.ttlSeconds < 0 ? "no expiry" : `${entry.ttlSeconds}s`}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}

/** Share of each labelled class that the gateway actually mitigated. */
function classRecall(outcomes: HttpOutcome[]): { label: string; value: number }[] {
  const grouped = new Map<string, { total: number; blocked: number }>();
  outcomes.forEach((entry) => {
    const bucket = grouped.get(entry.expected) ?? { total: 0, blocked: 0 };
    bucket.total += 1;
    if (entry.blocked) bucket.blocked += 1;
    grouped.set(entry.expected, bucket);
  });
  return [...grouped.entries()]
    .map(([name, value]) => ({ label: humanize(name), value: Number((value.blocked / value.total).toFixed(4)) }))
    .sort((first, second) => second.value - first.value);
}
