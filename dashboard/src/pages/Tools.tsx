import { useEffect, useRef, useState } from 'react';
import { Panel, Metric, Badge } from '../components/Ui';
import { modelCatalog, sampleNetworkCorpus, probeGateway, type ModelCatalog, type GatewayProbeResult } from '../api';
import { PROBE_LIBRARY, type ViewProps } from '../lib/view';
export function CachePage({ api }: ViewProps) {
    const [entries, setEntries] = useState<Awaited<ReturnType<typeof api.redis>>['entries']>([]), [cursor, setCursor] = useState('0'), [error, setError] = useState('');
    const load = async (next = '0') => { try {
        const result = await api.redis(next);
        setEntries(current => next === '0' ? result.entries : [...new Map([...current, ...result.entries].map(row => [row.key, row])).values()]);
        setCursor(result.cursor);
        setError('');
    }
    catch (e) {
        setError(String(e));
    } };
    useEffect(() => { void load(); }, [api]);
    return <div className="stack"><Panel title="Live Redis request state" subtitle="Read-only waf:* keys, types, expiration and bounded values. Expired keys may disappear during the scan." action={<button className="btn" onClick={() => void load()}>Refresh cache</button>}>
 {error && <p role="alert">{error}</p>}<div className="table-wrap"><table><thead><tr><th>Key</th><th>Type</th><th>TTL seconds</th><th>Current value / sample</th></tr></thead><tbody>{entries.map(row => <tr key={row.key}><td className="mono">{row.key}</td><td>{row.type}</td><td>{row.ttl}</td><td><pre className="code-block">{JSON.stringify(row.value, null, 2)}</pre></td></tr>)}</tbody></table></div><p>{entries.length} keys shown · collection values are samples of up to 25 elements.</p><button className="btn" disabled={cursor === '0'} onClick={() => void load(cursor)}>Load next keys</button></Panel></div>;
}
type QueryOutput = {
    stage?: string;
    error?: string;
    results?: {
        prediction: string;
        expected_model_label: string | null;
        matches_supplied_label: boolean | null;
        latency_ms: number;
        probabilities: Record<string, number>;
    }[];
};
export function ModelLab({ api, recordRun, runs }: ViewProps) {
    const [catalog, setCatalog] = useState<ModelCatalog>(), [stage, setStage] = useState('triage'), [algorithm, setAlgorithm] = useState('deployed'), [template, setTemplate] = useState(0), [input, setInput] = useState(JSON.stringify([PROBE_LIBRARY[0]], null, 2)), [result, setResult] = useState<unknown>(), [busy, setBusy] = useState(false), [error, setError] = useState('');
    useEffect(() => { void modelCatalog().then(setCatalog).catch(e => setError(String(e))); }, []);
    const query = async (all = false) => { setBusy(true); setError(''); try {
        const requests = JSON.parse(input);
        if (!Array.isArray(requests) || !requests.length || requests.length > 32)
            throw Error('Provide 1–32 request templates');
        const output = [];
        for (const selected of all ? ['triage', 'router', 'injection', 'execution', 'deep'] : [stage]) {
            try {
                output.push(await api.modelQuery({ stage: selected, algorithm: all ? 'deployed' : algorithm, requests }));
            }
            catch (e) {
                output.push({ stage: selected, error: String(e) });
            }
        }
        setResult(output);
        recordRun({ id: crypto.randomUUID(), kind: 'Model Lab', count: requests.length * output.length, results: output, summary: { models: output.length, modelOnly: true } });
    }
    catch (e) {
        setError(String(e));
    }
    finally {
        setBusy(false);
    } };
    const shown = (Array.isArray(result) ? result : runs.find(r => r.kind === 'Model Lab')?.results ?? []) as QueryOutput[];
    return <div className="stack"><Panel title="Model query laboratory" subtitle="Execute individual trained models without rule shortcuts. These probes do not pass through the gateway or change traffic totals."><div className="form-grid"><label className="field">Model<select value={stage} onChange={e => { setStage(e.target.value); setAlgorithm('deployed'); }}>{catalog?.stages.map(s => <option key={s.stage} value={s.stage}>{s.title}</option>)}</select></label><label className="field">Artifact<select value={algorithm} onChange={e => setAlgorithm(e.target.value)}><option value="deployed">Deployed artifact</option>{catalog?.stages.find(s => s.stage === stage)?.candidates.map(c => <option key={c.algorithm} value={c.algorithm}>{c.algorithm}</option>)}</select></label><label className="field">Request template<select value={template} onChange={e => { const index = Number(e.target.value); setTemplate(index); setInput(JSON.stringify([PROBE_LIBRARY[index]], null, 2)); }}>{PROBE_LIBRARY.map((p, i) => <option key={i} value={i}>{p.family} · {p.label}</option>)}</select></label></div><div className="btn-row"><button className="btn" onClick={() => setInput(JSON.stringify(PROBE_LIBRARY.slice(0, 32), null, 2))}>Load HTTP template suite</button><button className="btn" onClick={() => void sampleNetworkCorpus(1, []).then(r => setInput(JSON.stringify(r.samples, null, 2))).catch(e => setError(String(e)))}>Load network flow</button></div><label className="field">Editable request array (headers, cookies, body supported)<textarea rows={14} value={input} onChange={e => setInput(e.target.value)}/></label><div className="btn-row"><button className="btn primary" disabled={busy} onClick={() => void query()}>Query selected model</button><button className="btn" disabled={busy} onClick={() => void query(true)}>Query all HTTP models</button></div>{error && <p role="alert">{error}</p>}</Panel><Panel title="Model outputs" subtitle="Class probabilities, measured inference latency and artifact identity"><div className="table-wrap"><table><thead><tr><th>Model</th><th>Template</th><th>Expected for role</th><th>Predicted</th><th>Match</th><th>Inference ms</th></tr></thead><tbody>{shown.flatMap(model => model.results?.map((row, index) => <tr key={`${model.stage}-${index}`}><td>{model.stage}</td><td>{index + 1}</td><td>{row.expected_model_label ?? "Outside role / unlabeled"}</td><td>{row.prediction}</td><td>{row.matches_supplied_label === null ? "�" : row.matches_supplied_label ? "Yes" : "No"}</td><td>{row.latency_ms.toFixed(2)}</td></tr>) ?? [<tr key={model.stage}><td>{model.stage}</td><td colSpan={5}>{model.error}</td></tr>])}</tbody></table></div><p>Supplied template labels are diagnostic checks, not independent model accuracy evidence.</p><pre className="code-block">{JSON.stringify(shown, null, 2)}</pre></Panel></div>;
}
export function TimingPage({ api, recordRun, runs, refresh }: ViewProps) {
    const [count, setCount] = useState(100), [concurrency, setConcurrency] = useState(4), [template, setTemplate] = useState(0), [busy, setBusy] = useState(false), [progress, setProgress] = useState(0), [error, setError] = useState('');
    const cancel = useRef(false);
    useEffect(() => () => { cancel.current = true; }, []);
    const run = async () => {
        if (count < 1 || count > 10000 || concurrency < 1 || concurrency > 32) {
            setError('Use 1–10,000 requests and concurrency 1–32');
            return;
        }
        setBusy(true);
        setError('');
        setProgress(0);
        cancel.current = false;
        const id = crypto.randomUUID(), rows: GatewayProbeResult[] = [];
        let next = 0;
        const started = performance.now();
        try {
            const worker = async () => { while (!cancel.current && next < count && performance.now() - started < 120000) {
                next++;
                try {
                    rows.push(await probeGateway(PROBE_LIBRARY[template]));
                }
                catch (e) {
                    rows.push({ label: 'Failed', method: 'GET', target: '', status: 0, blocked: false, roundTripMs: 0, bodyPreview: '', error: String(e) });
                }
                setProgress(rows.length);
            } };
            await Promise.all(Array.from({ length: concurrency }, worker));
            const elapsed = (performance.now() - started) / 1000, values = rows.map(r => r.roundTripMs).sort((a, b) => a - b), q = (fraction: number) => values[Math.min(values.length - 1, Math.floor((values.length - 1) * fraction))] ?? 0;
            const ids = rows.flatMap(r => r.requestId ? [r.requestId] : []);
            const joined = await api.awaitJournal(ids.slice(-200));
            const events = await api.events({ limit: 500 });
            const lookup = new Map(events.events.map(e => [e.requestId, e]));
            const covered = rows.filter(r => r.requestId && lookup.has(r.requestId));
            const full = covered.filter(r => lookup.get(r.requestId)?.inspectionStatus === 'FULLY_INSPECTED').length;
            recordRun({ id, kind: 'Timing', count: rows.length, results: rows.slice(-200), summary: { requested: count, completed: rows.length, samplesRetained: Math.min(200,rows.length), elapsedSeconds: elapsed, httpResponsesPerSecond: rows.filter(r => r.status > 0).length / elapsed, successful2xx: rows.filter(r => r.status >= 200 && r.status < 300).length, p50Ms: q(.5), p95Ms: q(.95), p99Ms: q(.99), errors: rows.filter(r => r.status === 0 || r.status >= 500).length, rateLimited: rows.filter(r => r.status === 429).length, blocked403: rows.filter(r => r.status === 403).length, ruleOnlyObserved: covered.filter(r => lookup.get(r.requestId)?.inspectionStatus === 'RULES_ONLY').length, partiallyInspectedObserved: covered.filter(r => lookup.get(r.requestId)?.inspectionStatus === 'PARTIALLY_INSPECTED').length, journalWindowMatched: covered.length, fullyInspectedObserved: full, fullyInspectedLowerBoundPerSecond: full / elapsed, unmatched: rows.length - covered.length, journalTail: joined, cancelled: cancel.current } });
            await refresh();
        }
        catch (e) {
            setError(String(e));
        }
        finally {
            setBusy(false);
        }
    };
    const last = runs.find(r => r.kind === 'Timing');
    return <div className="stack"><Panel title="Gateway timing bench" subtitle="Owned gateway only; at most 10,000 requests, 32 concurrent workers and a 120-second dispatch budget. In-flight requests finish or time out; policy enforcement remains active."><div className="form-grid"><label className="field">Requests<input type="number" min={1} max={10000} value={count} onChange={e => setCount(Number(e.target.value))}/></label><label className="field">Concurrency<input type="number" min={1} max={32} value={concurrency} onChange={e => setConcurrency(Number(e.target.value))}/></label><label className="field">Template<select value={template} onChange={e => setTemplate(Number(e.target.value))}>{PROBE_LIBRARY.map((p, i) => <option key={i} value={i}>{p.label}</option>)}</select></label></div><div className="btn-row"><button className="btn primary" disabled={busy} onClick={() => void run()}>Run timing test</button><button className="btn danger" disabled={!busy} onClick={() => { cancel.current = true; }}>Stop new requests</button><Badge value={`${progress} completed`} tone="info"/></div>{error && <p role="alert">{error}</p>}</Panel>{last && <><div className="grid-3"><Metric label="Requests completed" value={last.count}/><Metric label="p95 client round trip" value={`${Number(last.summary?.p95Ms ?? 0).toFixed(2)} ms`}/><Metric label="HTTP responses / s" value={Number(last.summary?.httpResponsesPerSecond ?? 0).toFixed(2)}/><Metric label="p50 client round trip" value={`${Number(last.summary?.p50Ms??0).toFixed(2)} ms`}/><Metric label="p99 client round trip" value={`${Number(last.summary?.p99Ms??0).toFixed(2)} ms`}/><Metric label="Errors" value={Number(last.summary?.errors??0)}/></div><Panel title="Timing results" subtitle="Client → control replay → gateway → backend. Full-run percentiles; latest 200 response samples retained. Fully inspected counts include only matched journal evidence; rate-limited/rule-only responses are separate."><pre className="code-block">{JSON.stringify(last.summary, null, 2)}</pre><button className="btn" onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(last, null, 2)], { type: 'application/json' })); const a = document.createElement('a'); a.href = url; a.download = 'timing-run.json'; a.click(); URL.revokeObjectURL(url); }}>Export summary and samples</button></Panel></>}</div>;
}
type RoutingReport = {
    data_origin?: string;
    results?: {
        seed: number;
        constrained: boolean;
        training_rows: number;
        evaluation_rows: number;
        mean_reward: number;
    }[];
    static_baselines?: Record<string, number>;
};
export function RoutingTraining({ api, recordRun, runs }: ViewProps) {
    const [input, setInput] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState(''), [saved, setSaved] = useState<Awaited<ReturnType<typeof api.routingRuns>>['runs']>([]), [report, setReport] = useState<unknown>();
    useEffect(() => { void api.routingRuns().then(result => setSaved(result.runs)).catch(e => setError(String(e))); }, [api, runs]);
    const run = async (simulation = false) => { setBusy(true); setError(''); try {
        const report = simulation ? await api.validateRouting() : await api.trainRouting(JSON.parse(input));
        setReport(report);
        recordRun({ id: String(report.run_id), kind: 'RL Training', count: 6, results: [report], summary: { shadowOnly: true, elapsedSeconds: report.elapsed_seconds } });
    }
    catch (e) {
        setError(String(e));
    }
    finally {
        setBusy(false);
    } };
    const shown = (report ?? runs.find(r => r.kind === 'RL Training')?.results[0] ?? {}) as RoutingReport;
    return <div className="stack"><Panel title="Offline routing training" subtitle="Train constrained and unconstrained LinUCB with three seeds. No live exploration or automatic deployment."><p>Upload reviewed route outcomes with separate development/evaluation IDs and groups. Required fields: review_reference, model_versions, development, evaluation. Rows use VERIFIED labels, pre_action_context and measured outcomes. Maximum 1,000 rows per population.</p><label className="field">Import route dataset<input type="file" accept="application/json,.json" onChange={e => { const file = e.target.files?.[0]; if (file && file.size <= 2000000)
        void file.text().then(setInput);
    else
        setError('Select a JSON file up to 2 MB'); }}/></label><label className="field">Dataset JSON<textarea rows={14} value={input} onChange={e => setInput(e.target.value)}/></label><button className="btn primary" disabled={busy || !input} onClick={() => void run()}>Train and validate routing</button><button className="btn" disabled={busy} onClick={() => void run(true)}>Run controlled RL validation</button><p>Controlled validation uses simulated outcomes and prescribed costs; it does not validate real attack detection.</p>{error && <p role="alert">{error}</p>}</Panel><Panel title="Saved routing runs"><div className="table-wrap"><table><thead><tr><th>Run</th><th>Population</th><th>Training seconds</th><th>Report</th></tr></thead><tbody>{saved.map(run => <tr key={run.run_id}><td>{run.run_id}</td><td>{run.data_origin}</td><td>{run.elapsed_seconds.toFixed(3)}</td><td><button className="btn" onClick={() => void api.routingRun(run.run_id).then(setReport).catch(e => setError(String(e)))}>Load report</button></td></tr>)}</tbody></table></div></Panel><Panel title="Routing experiment results" subtitle="Mean reward, static baselines, evaluation decisions and constraints; retained artifacts remain shadow-only"><Badge value={shown.data_origin ?? "No experiment selected"} tone="info"/><div className="table-wrap"><table><thead><tr><th>Seed</th><th>Policy</th><th>Train / evaluation</th><th>Mean reward</th></tr></thead><tbody>{shown.results?.map(row => <tr key={`${row.seed}-${row.constrained}`}><td>{row.seed}</td><td>{row.constrained ? "Constrained LinUCB" : "Unconstrained LinUCB"}</td><td>{row.training_rows} / {row.evaluation_rows}</td><td>{row.mean_reward.toFixed(4)}</td></tr>)}</tbody></table></div><p>Static baseline rewards: {JSON.stringify(shown.static_baselines ?? {})}</p><pre className="code-block">{JSON.stringify(shown, null, 2)}</pre></Panel></div>;
}
