# Reproduce the research checkpoint

Use PowerShell in `C:\Projects\Adaptive Waf Ids`, Java/Maven/Node/Docker and the existing `.venv`. Model/data downloads and training are not part of these safe commands. Each output path below must be new. The scripts refuse to overwrite prior evidence.

## Complete verification and isolated dependencies

```powershell
Set-Location -LiteralPath 'C:\Projects\Adaptive Waf Ids'
docker compose -p adaptive-waf-research -f research/compose.integration.yml up -d --pull never
$env:WAF_TEST_REDIS_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port redis 6379).Split(':')[-1]
$env:WAF_TEST_RABBIT_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port rabbitmq 5672).Split(':')[-1]
$env:WAF_TEST_POSTGRES_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port postgres 5432).Split(':')[-1]
.\scripts\verify_research.ps1 -RunId reproduced-acceptance-001 -Integration
```

This runs every Java module's tests, full Python unittest discovery and the dashboard TypeScript/Vite build. Without `-Integration`/fixture environment variables, the dependency tests skip; such a run does not prove broker/database behavior. Native loopback sockets and Mockito self-attachment may need execution outside a restricted sandbox. The fixtures use cached images, random loopback ports and a tmpfs database, with no user data volumes.

Equivalent individual commands:

```powershell
mvn -o -f gateway-service/pom.xml '-DargLine=-XX:+EnableDynamicAgentLoading -Djdk.attach.allowAttachSelf=true' test
mvn -o -f security-control-service/pom.xml '-DargLine=-XX:+EnableDynamicAgentLoading -Djdk.attach.allowAttachSelf=true' test
mvn -o -f demo-backend/pom.xml '-DargLine=-XX:+EnableDynamicAgentLoading -Djdk.attach.allowAttachSelf=true' test
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
npm.cmd --prefix dashboard run build
```

## Real gateway/static strategy comparisons

```powershell
mvn -o -f gateway-service/pom.xml package -DskipTests
mvn -o -f security-control-service/pom.xml package -DskipTests
mvn -o -f demo-backend/pom.xml package -DskipTests
.\.venv\Scripts\python.exe -m scripts.benchmark_gateway_research --output research/runs/reproduced-gateway-001 --concurrency 1,4 --repeats 2 --additional-strategies single_fast,always_deep,confidence,cost_threshold,calibrated_fusion,deep_only_control
.\.venv\Scripts\python.exe -m scripts.profile_model_threads --output research/runs/reproduced-threads-001.json
.\.venv\Scripts\python.exe -m scripts.profile_deep_devices --output research/runs/reproduced-devices-001.json --repeats 3
.\.venv\Scripts\python.exe -m scripts.plot_research --gateway research/runs/reproduced-gateway-001/metrics.json --threads research/runs/reproduced-threads-001.json --devices research/runs/reproduced-devices-001.json --output research/figures/reproduced-001
```

The runner owns/stops its Java and HTTP processes, joins actual gateway decisions from PostgreSQL by UUID, archives measured source, and records configuration/model hashes and environment. It never trains or reads the reserved final split. The default six probes are development diagnostics. `--input <reviewed-development.json>` accepts a bounded development envelope described in `methods_and_blockers.md`; it does not establish that the input is representative or independently labeled. Do not run UI fixtures or other benchmarks concurrently when comparing process cost. GPU device samples can include unrelated workloads. Repeat independent complete runs to study variability; repeating the same probes does not produce independent security evidence.

Derived summaries can be reproduced without rewriting the measured report:

```powershell
.\.venv\Scripts\python.exe -m scripts.derive_research_summary --input research/runs/reproduced-gateway-001/metrics.json --output research/runs/reproduced-gateway-001/derived_summary.json
```

## Pinned CRS-only baseline

The cached image is digest-pinned. The current packaged demo backend JAR is mounted read-only behind CRS, without the adaptive gateway.

```powershell
$crsListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$crsListener.Start()
$env:WAF_CRS_TEST_PORT = [string]$crsListener.LocalEndpoint.Port
$crsListener.Stop()
docker compose -p adaptive-waf-crs-research -f research/compose.crs.yml up -d --pull never
.\.venv\Scripts\python.exe -m scripts.benchmark_crs --url "http://127.0.0.1:$env:WAF_CRS_TEST_PORT" --output research/runs/reproduced-crs-001
docker compose -p adaptive-waf-crs-research -f research/compose.crs.yml stop
```

Wait for the CRS fixture's health to become healthy before benchmarking. Container timing differs from the host-JVM experiment. The CRS report records binary enforcement interventions; exact attack-class ML metrics are unavailable. No image pull occurs. If the pinned image is absent, request download approval instead of silently pulling it.

## Browser fixture

```powershell
$env:WAF_RESEARCH_RESULTS_PATH = 'research/runs/gateway-comparison-v7/metrics.json'
$env:WAF_CONTEXT_MODE = 'shadow'
$env:WAF_MODEL_THREADS = '1'
.\.venv\Scripts\python.exe -m scripts.serve_research_fixture --output research/runs/reproduced-ui-001
```

Read `research/runs/reproduced-ui-001/urls.json` after readiness, then sign in with the explicitly disposable fixture identity `fixture-admin` / `local-fixture-only`. This is not a user credential or production configuration. To stop gracefully from another shell:

```powershell
Set-Content -LiteralPath research/runs/reproduced-ui-001/STOP -Value stop
```

The fixture runs synchronous deep inference and shadow context, starts the existing sensor/adaptation services, and passes the actual DB port to the client-connection display. `browser_qa.md` records executed workflows. The Research page uses measured data, with absent calibration/reward/reference values explicitly unavailable. Operator reviews in PostgreSQL and joined labels in the detection monitor have distinct scopes; one is not automatically treated as the other.

## Deployment flags, migration and rollback

`WAF_DETECTION_STRATEGY=fixed` is the original default. `guarded_fixed`, `rules_only`, `single_fast`, `both`, `always_deep`, `confidence`, `cost_threshold`, `calibrated_fusion`, `conformal` and `bandit_shadow` are opt-in candidates. `WAF_CONFORMAL_ARTIFACT` and `WAF_BANDIT_ARTIFACT` require matching model versions. Leave context flags unset to disable context. `WAF_CONTEXT_MODE=shadow` is evidence-only; simulation is for controlled fixtures. Configure an explicit >=32-character `WAF_SESSION_HMAC_SECRET` for session correlation; no IP fallback is used. `WAF_ENDPOINT_PROFILE_ARTIFACT` loads a reviewed frozen profile.

`WAF_MODEL_THREADS=1` selects the measured thread option; omit it to restore original estimator settings. `WAF_DEEP_DEVICE=cpu` forces CPU, `auto` selects available CUDA. CUDA OOM retries on CPU; failed native work still retains execution capacity until it ends. Previous model/config files and the source at `12a6a4a` remain available.

The durable deep adapter requires `WAF_DEEP_QUEUE_BACKEND=rabbitmq`, `WAF_DEEP_POSTGRES_DSN` and `WAF_DEEP_RABBITMQ_URL` plus additive Flyway V6. Set the same private `WAF_INTERNAL_TOKEN` in service processes without printing it. Do not expose demo defaults. Topology v2 uses separate job/dead queues; existing v1 queues are untouched and require an operator-controlled drain/migration. No automatic transfer or deletion is performed. Omit the adapter flag to use the prior in-process worker.

Runtime policies are prepared through authenticated `/internal/v1/research/policies`; promotion additionally requires `WAF_LIVE_ACTIVATION_ENABLED=true`, a non-shadow reviewed candidate, empirical gates and an operator approval reference. No live promotion command was run. Registry status alone is not runtime activation. Source rollback should use a separate checkout, preserving current changes; retain additive DB columns and normal Flyway history rather than deleting schemas.

`DETECTION_FAIL_CLOSED=false` preserves the existing fail-open default. Explicit outage/partial coverage is returned. `DETECTION_FAIL_CLOSED=true` rejects unavailable/required-uninspected decisions. Trusted proxy addresses, body byte/read limits and local bindings are documented in configuration. Multipart/compressed/binary bodies are explicitly rejected until supported, which is the documented inspection migration.

## Cleanup

After owned HTTP fixtures finish:

```powershell
docker compose -p adaptive-waf-research -f research/compose.integration.yml stop
Remove-Item Env:WAF_TEST_REDIS_PORT, Env:WAF_TEST_RABBIT_PORT, Env:WAF_TEST_POSTGRES_PORT -ErrorAction SilentlyContinue
Remove-Item Env:WAF_CONTEXT_MODE, Env:WAF_MODEL_THREADS, Env:WAF_RESEARCH_RESULTS_PATH -ErrorAction SilentlyContinue
```

No `down -v`, prune, recursive repository clean, source reset or user-volume deletion is needed. Stopped tmpfs fixture DB contents are not durable research evidence; committed JSON/test reports are the evidence.

Expensive candidate training remains ON HOLD. Prepared commands and data requirements are in `training_approval.md` and `methods_and_blockers.md`; do not run them merely to reproduce this checkpoint.

For the separate all-deep control used in V8, run the same benchmark with `--additional-strategies deep_only_control --only-modes deep_only_control_gateway` and a fresh output directory. The combined historical view is simply the concatenation of V7 and V8 experiment arrays after checking identical input_sha256, with both source hashes retained; it is not a new measured trial.

The observed dependency versions are recorded in `requirements-observed.txt`. This is an inventory of this Windows environment, including its CUDA-specific Torch build, not a promise that vanilla PyPI can reproduce every wheel on another Python/OS version. Optional research plotting requires the compatible matplotlib/psutil research extra. Do not initiate a large CUDA/runtime download as part of the held training task without approval.

## Candidate population audit (no training)

These commands read only legacy train/validation. Select NEW output directories to preserve existing evidence. The group-held-out candidate population is small and is not representative real-world acceptance. Do not score final evaluation while changing configurations.

```powershell
.\.venv\Scripts\python.exe -m scripts.audit_http_population --output artifacts/research/audits/http-v2-20261028-02
.\.venv\Scripts\python.exe -m scripts.prepare_candidate_protocol --audit artifacts/research/audits/http-v2-20261028-02 --output artifacts/research/protocols/http-v2-20261028-02
.\scripts\verify_research.ps1 -RunId representation-readiness-v21 -Integration
```

These exact IDs already exist and commands refuse overwrite; choose new IDs for a reproduction. The verifier resolves isolated Docker ports and checks Redis PONG, an AMQP channel, and PostgreSQL SELECT 1 before tests. Baseline V16 preserves the broker-startup race, V21 records successful acceptance.

## Bounded candidate experiment

Read `candidate_training_approval.md` for population limits and the pending approval. Read-only preflight:

```powershell
.\.venv\Scripts\python.exe -m scripts.candidate_experiments --config configs/models/candidate_experiment_v2.toml
```

After explicit approval only, append `--execute --output artifacts/research/experiments/model-only-v2-20261028-01`. Existing output paths are refused. All models fit before final scoring; no candidate replaces active models. Checkpoints and manifests permit reviewed recovery into a separate directory. The 90-minute supervisor includes fits and scoring; CPU fallback can exhaust that budget without completing all runs.

## Docker release

Use `../infra/docker/release/DEPLOYMENT.md` and `docker_release_status.md`. Seven tagged application images plus four pinned infrastructure images are included in the verified portable CPU bundle. `.env` stays private. `scripts/release.ps1` provides Build/Start/Health/Smoke/Logs/Stop/Export/Import; regular Stop never deletes volumes. Actual import acceptance uses no build or pull.

## Connected operator tools

See `operator_tools.md`. Reproduce live API checks with `.\.venv\Scripts\python.exe -m scripts.verify_operator_tools --output research/runs/new-tools-http`. Browser checks use `scripts/browser_operator_tools.cjs` with a new WAF_BROWSER_REPORT_ROOT and optional WAF_TIMING_REQUESTS. New source/runtime images are v1.1.0; older archives remain unchanged.
