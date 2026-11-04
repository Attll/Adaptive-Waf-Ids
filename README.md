# Adaptive WAF-IDS

The versioned Docker release is described in [deployment instructions](infra/docker/release/DEPLOYMENT.md). It packages independently deployable services and curated baseline models. Use `scripts/release.ps1` to build, start, check, smoke-test, export, import and stop the release. Runtime verification status is recorded in `research/docker_release_status.md`; a successful build alone is not operational acceptance.

Adaptive WAF-IDS is a local, multi-service web-application firewall demonstration that classifies HTTP requests and network-flow context, applies gateway enforcement, and journals security decisions. It combines a Spring Cloud Gateway, a Python model-serving API backed by saved artifacts, Redis state, RabbitMQ event delivery, PostgreSQL control-plane storage, and a React operator console.

The project exists to demonstrate an adaptive decision path rather than a single classifier: request-shape models identify HTTP attack categories, Redis supplies recent behavioural and flow context, a control plane supplies policy and auditability, and a deferred deep-model path can revise uncertain fast decisions. The repository includes saved training and evaluation results; this README describes those artifacts and does not require retraining to understand or operate the system.

## Features

- HTTP detection for benign, SQL injection, cross-site scripting (XSS), cookie injection, directory traversal, and remote-code-execution labels.
- A separate CICIDS-trained flow classifier (live extractor equivalence remains unverified) producing `BRUTE_FORCE`, `DOS_DDOS`, and `BOT_ANOMALY` context.
- Redis-backed rolling behaviour counters, temporary source blocks, load shedding, and short-lived network evidence.
- Synchronous gateway blocking and a bounded asynchronous deep-adjudication path for low-confidence fast verdicts.
- RabbitMQ-backed security-event journalling to PostgreSQL, authenticated control APIs, and a ticketed WebSocket feed.
- A dashboard, a demo upstream application, saved model artifacts, datasets, benchmark outputs, and test suites.

## Table of contents

- [1. System overview](#1-system-overview)
- [2. High-level architecture](#2-high-level-architecture)
- [3. Architecture at a glance](#3-architecture-at-a-glance)
- [4. Repository structure](#4-repository-structure)
- [5. Components and services](#5-components-and-services)
- [6. Request and transaction lifecycle](#6-request-and-transaction-lifecycle)
- [7. Data model and persistence](#7-data-model-and-persistence)
- [8. Detection and model pipeline](#8-detection-and-model-pipeline)
- [9. Threat categories and decisions](#9-threat-categories-and-decisions)
- [10. Failure and fallback behaviour](#10-failure-and-fallback-behaviour)
- [11. Observed runtime characteristics](#11-observed-runtime-characteristics)
- [12. APIs and interfaces](#12-apis-and-interfaces)
- [13. Configuration](#13-configuration)
- [14. Running and verifying the project](#14-running-and-verifying-the-project)
- [15. Testing](#15-testing)
- [16. Technology and design notes](#16-technology-and-design-notes)
- [17. Limitations](#17-limitations)
- [18. Complete system diagram](#18-complete-system-diagram)

## 1. System overview

The primary protected route is `/backend/**` on the gateway. A request is correlated with an `X-Request-ID`, assessed for load and behavioural state in Redis, supplied with any network-sensor evidence, and sent to the detection service when the gateway is in a model-permitting mode. If the final detection risk exceeds the control-plane threshold, the gateway returns a JSON `403`; otherwise it forwards the request to the demo backend. The decision is published asynchronously for persistence and live display.

System boundaries are intentionally local in the supplied Compose topology. The services run on one Docker network, while Redis, RabbitMQ, PostgreSQL, gateway, model service, sensor, adaptation API, dashboard, and CRS entrypoint have selected host ports. The repository contains no third-party identity provider, cloud control plane, external queue, or remote model registry.

## 2. High-level architecture

```text
 ┌─────────┐ HTTP ┌─────────────────┐ HTTP ┌─────────────────┐
 │ Client  ├─────►│ Optional CRS    ├─────►│ Gateway :8080   ├──► Demo backend
 └─────────┘      │ ModSecurity:8090│      └──────┬─────┬────┘    (internal :8081)
                  └─────────────────┘             │     │
                          HTTP /v1/detect ────────┘     └── Redis protocol ──► [Redis :6379]
                                  │                         AMQP topic
                                  ▼                              ▼
                         [Detection API :8000]          [RabbitMQ :5672]
                                  │ HTTP escalation              │ security.#
                                  ▼                              ▼
                         [Control service :8082] ◄──── JDBC ───► [PostgreSQL]
                                  ▲        ▲
           lifecycle HTTP ───────┘        └── HTTP/WebSocket proxy ── [Dashboard :3000]
            [Adaptation API :8084]        [Sensor :8083] ── SET evidence ──► Redis
```

The optional CRS container is an OWASP ModSecurity CRS Nginx image whose upstream is the gateway. It is separate from the Python/ML decision pipeline. The `detection-service/Dockerfile` copies the saved `artifacts/training` tree into its image; it does not train models.

## 3. Architecture at a glance

| Component | Responsibility | Technology | Communicates with |
| --- | --- | --- | --- |
| Gateway | Request interception, Redis behaviour checks, enforcement, forwarding, event publication | Java 21, Spring Boot, Spring Cloud Gateway | detection, Redis, RabbitMQ, control, demo backend |
| Detection service | Loads deployed artifacts and serves HTTP and network inference APIs | Python, FastAPI, scikit-learn, PyTorch/Transformers | gateway, control for deferred escalations |
| Network sensor | Validates flow features, classifies a flow, writes short-lived source context | Python, FastAPI, raw Redis protocol | Redis, gateway indirectly |
| Control service | Admin APIs, policy cache source, event consumer, journal, WebSocket feed | Java 21, Spring Boot, JPA/JDBC, Flyway | PostgreSQL, Redis, RabbitMQ, dashboard, adaptation API |
| Adaptation API | Curates feedback metadata, registers candidate lifecycle records, calculates PSI | Python, FastAPI | control service, filesystem |
| Dashboard | Operator console and replay/inspection UI | React 19, TypeScript, Vite, Nginx | all HTTP services and control WebSocket |
| Demo backend | Deliberately simple upstream used to prove forwarding | Java 21, Spring Boot MVC | gateway |
| Redis | Behaviour counters, blocks, operating mode, network evidence | Redis 7.4 | gateway, sensor, control |
| RabbitMQ | Durable security-event transport | RabbitMQ 3.13 | gateway producer, control consumer |
| PostgreSQL | Security journal, control-plane records, audit history | PostgreSQL 16 | control service |

## 4. Repository structure

```text
Adaptive-Waf-Ids/
├── configs/                     # Core, data, model deployment and threshold TOML
├── datasets/
│   ├── samples/                 # Shipped HTTP and network replay corpus
│   ├── raw/                     # Ignored raw ATRDF/CICIDS sources
│   └── processed/               # Ignored prepared JSONL splits and manifests
├── artifacts/                   # Ignored saved model, calibration, benchmark, evaluation output
├── src/adaptive_waf/
│   ├── service/                 # Detection FastAPI service and deferred escalation worker
│   ├── runtime/                 # Artifact loading, pipeline, fusion, policy, network runtime
│   ├── features/                # Request canonicalisation and classical feature extraction
│   ├── training/                # Offline dataset, training, calibration and evaluation utilities
│   ├── data/                    # ATRDF/CICIDS preparation and inspection
│   ├── network_sensor/          # Flow accumulator, Redis writer, sensor API
│   └── adaptation/              # Feedback curation and PSI adaptation API
├── gateway-service/             # Gateway Spring Boot application
├── security-control-service/    # Control-plane Spring Boot application and Flyway migrations
├── demo-backend/                # Example protected backend
├── dashboard/                   # React/Vite console and Nginx proxy configuration
├── detection-service/           # Detection container definition
├── network-sensor/              # Sensor container definition
├── training-adaptation-service/ # Adaptation container definition
├── infra/docker/                # Compose files for platform phases
├── scripts/                     # Preparation, training, inspection, benchmark and verification commands
├── tests/                       # Python unit and integration-style tests
└── pyproject.toml               # Python package and optional dependency groups
```

`artifacts/` and the raw/processed dataset directories are intentionally ignored by Git. They contain the saved data required for the deployed model paths, but are not source code. `target/`, `.venv/`, `dashboard/node_modules/`, and `dashboard/dist/` are generated local directories.

## 5. Components and services

### Gateway service

`AdaptiveDetectionFilter` is a global reactive filter. It excludes `/actuator/**`, limits the inspected body to `DETECTION_MAX_BODY_BYTES` (default 65,536 bytes), removes transport and sensitive headers before model submission, and reinserts a buffered body for the upstream route. It tracks a request-id, passes the current behaviour and network context to `/v1/detect`, and enforces the cached block threshold.

Redis keys implement the runtime state:

- `waf:ip:<source>:requests:short` and `:medium`: sorted-set rolling request counters.
- `waf:ip:<source>:endpoint:<sha256(path)>`: rolling per-endpoint count.
- `waf:login:<source>:failures` and `waf:ip:<source>:attacks`: expiring counters.
- `waf:block:<source>`: temporary or operator/manual block.
- `waf:system:requests:short` and `waf:system:mode`: global load-mode state.
- `waf:network:<source>`: JSON flow evidence supplied by the sensor.

The default 10-second request window changes operating mode at 20 (ELEVATED), 40 (DEGRADED), and 80 (EMERGENCY) requests. Only NORMAL and ELEVATED permit model inference. At 40 short-window requests, the source is rate-limited; a temporary block is also written at the configured threshold. Five unsuccessful requests whose path contains `login` can create a temporary block. The filter has a 250 ms Redis-operation timeout.

`GatewayPolicy` refreshes `/internal/v1/gateway-policy` on startup and every 30 seconds. If that request fails, it keeps the last cached policy. `SecurityEventPublisher` sends events on a bounded in-process executor (capacity 500); broker errors and executor saturation are logged and events are dropped rather than preventing the request path.

### Detection service

`adaptive_waf.service.app` is a FastAPI application. Its `RuntimeStore` loads the HTTP hierarchy and network classifier once at startup, serialises inference through an `RLock`, records an artifact-load error rather than exposing a partial runtime, and enforces 30,000 ms HTTP and 5,000 ms network inference ceilings. `/ready` returns `503` when those artifacts cannot load.

`/v1/detect` accepts method, path, query, headers, cookies, body, source IP, optional behaviour/network contexts, and optional direct-API `rule_evidence`. The gateway supplies all except rule evidence. The response includes stage latencies, model versions, route, class scores, risks, and escalation status. `/v1/detect/batch` evaluates up to 100 submitted request payloads.

The deep predictor uses a saved DistilBERT tokenizer/model and a saved temperature. A configured CUDA device falls back to CPU if CUDA is unavailable. When a fast expert’s confidence is below `0.90`, the service either performs deep inference inline or—by the deployed configuration—queues a deferred adjudication. The in-memory worker has two daemon threads, a maximum queue depth of 256, retains 200 outcomes, and optionally POSTs resolutions to the control service.

### Network sensor

The sensor’s `/v1/flows` input is an IP pair plus a complete, schema-validated feature map. `OfflineNetworkDetector` rejects missing, unexpected, or non-finite values. The classifier’s risk is `1 - P(BENIGN)`, with the most likely class and its probability retained as context. `NetworkSensor` normalises IP addresses and writes JSON to Redis with a 300-second TTL. The gateway reads the same source key with a 25 ms timeout; absent, malformed, or unavailable data resolves to an empty (risk 0) context.

`capture_network_flows.py` can produce the supported CICIDS-compatible fields from TCP/UDP packet observations using optional Scapy. `replay_network_flows.py` submits saved prepared flows. These are utilities; no packet capture runs automatically.

### Security control service

The control service authenticates non-internal `/v1/**` requests with HTTP Basic and a BCrypt-hashed administrator stored in `admin_users`. Health/info, `/internal/**`, and stream endpoints are exempt by configuration. The initial administrator is created only when absent; documentation deliberately does not repeat its configured development secret.

The service declares topic exchange `adaptive.waf.events`, durable queue `security.events.persist`, and `security.#` binding. `SecurityEventConsumer` parses each JSON event, deduplicates by event id, redacts recursively named credential fields, stores a `security_events` row inside the listener transaction, then broadcasts the persisted event. A ticket obtained from the authenticated stream-ticket endpoint is required for the `/v1/stream/events` WebSocket handshake.

`ControlPlaneService` provides applications, active policy, blocks, model registry/assignment, feedback, and audit records. Its changing operations are marked `@Transactional`. A manual or escalation block is recorded in both `blocked_entities` and Redis. Deferred deep revisions are independently journalled; if a changed non-benign verdict reaches risk `0.81` or more, the default escalation configuration writes a 15-minute source block.

### Adaptation API, dashboard, and demo backend

The adaptation service is lifecycle/metadata tooling, not a training runner. It exports feedback as sanitised metadata-only JSONL, registers a candidate/challenger through the internal control API, and computes population stability index (PSI): `<0.1` is `STABLE`, `<0.25` is `MONITOR`, otherwise `SHADOW_RECOMMENDED`. It does not automatically promote a model or change policy.

The dashboard’s Nginx configuration proxies `/control-api/`, `/control-ws/`, `/gateway-api/`, `/detection-api/`, `/sensor-api/`, and `/adaptation-api/` to their respective services. The demo backend exposes health, search, login, echo, and a catch-all handler solely so that forwarded/replayed traffic reaches an upstream.

## 6. Request and transaction lifecycle

```text
 Client          Gateway             Redis        Detection       Upstream       RabbitMQ       Control/DB
   │ HTTP           │                   │              │              │              │               │
   ├───────────────►│                   │              │              │              │               │
   │                ├── windows/block ─►│              │              │              │               │
   │                │◄── state/context ─┤              │              │              │               │
   │                ├── POST /detect ─────────────────►│              │              │               │
   │                │◄── risk/route/evidence ──────────┤              │              │               │
   │   403/429 ◄────┤  (block/rate-limit branch)        │              ├─event──────►│──persist─────►│
   │ OR             │                                   │              │              │               │
   │                ├── original request ────────────────────────────►│              │               │
   │                │◄── response ───────────────────────────────────┤              │               │
   │◄── response ──┤── security.request (async) ───────────────────────────────────►│──redact/save─►│
```

Detection itself is a separate transaction-free in-memory computation. The persistence transaction begins in `SecurityEventConsumer.consume` after RabbitMQ delivery and commits the journal row. The gateway’s event publisher is explicitly asynchronous, so a forwarded or blocked response is not contingent on journal persistence.

For an uncertain fast verdict, the first response can be forwarded while the detection worker evaluates DistilBERT. The worker sends its resolution to `/internal/v1/security/escalations`; the control service journals it and can block subsequent requests from the source. This is not a rollback of the already-forwarded request.

### Transaction and data flow

```text
 [Gateway request] -> [Detection JSON] -> [scores / risks / route / timings] -> [Gateway decision]
                                      ^                                      |
 [Sensor flow] -> [NetworkEvidence + TTL] -> [Redis waf:network:*] ---------+
                                      |
                         [SecurityEvent JSON] -> [AMQP security.#]
                                      -> [sanitize credential-named fields]
                                      -> [security_events row] -> [WebSocket frame]
```

The gateway builds its event before it forwards or returns a security response, but the record is only durable after the AMQP consumer saves it. The entity listener transaction makes the event-row write atomic with respect to that listener invocation. There is no cross-service transaction, retry orchestration in the gateway, or rollback of a forwarded upstream request.

## 7. Data model and persistence

```text
 [PROTECTED_APPLICATIONS] 1 ──< [POLICY_VERSIONS]
 [PROTECTED_APPLICATIONS] 1 ── 0..1 [MODEL_ASSIGNMENTS] >── 1 [MODEL_VERSIONS]
 [MODEL_VERSIONS]        1 ──< [MODEL_METRICS]
 [ADMIN_USERS]           1 ──< [AUDIT_LOG]
 [SECURITY_EVENTS]       1 ──< [ADMIN_FEEDBACK]
```

Flyway migrations define the following PostgreSQL data:

| Table | Purpose |
| --- | --- |
| `security_events` | Request and escalation journal: decision, request metadata, model evidence JSON, timings, route and confidence. Indexed by time, category, source IP, action and predicted attack. |
| `admin_users` | Username, BCrypt password hash, role, creation time. |
| `protected_applications` / `policy_versions` | Registered upstreams and one active version per application. A `demo-backend` default row is seeded. |
| `blocked_entities` | Durable source-block records. Redis carries the enforcement copy. |
| `model_versions`, `model_assignments`, `model_metrics` | Model inventory, application assignment, and named numeric metrics. |
| `admin_feedback` | Operator feedback, including optional corrected attack type. |
| `training_runs` | Lifecycle record with artifact URI, metrics JSON, drift JSON and shadow-mode flag. |
| `audit_log` | Old/new JSON representations of control-plane changes. |

Redis is not a cache of PostgreSQL records: it holds short-lived enforcement/runtime state. RabbitMQ supplies a durable queue but the gateway publisher can still drop an event before sending if its local executor is full or the broker call fails.

## 8. Detection and model pipeline

```text
 HTTP method/path/query/headers/cookies/body
                    │
                    ▼
          [canonical text] -> [24 features] -> [calibrated RF triage]
                                                      │
                                                      ▼
                                           [calibrated logistic router]
                                               ┌──────┴──────┐
                                               ▼             ▼
                                      [Injection RF]  [Execution ET]
                                               └──────┬──────┘
                                                      ▼
                                  fast confidence < .90? ──yes──> [DistilBERT]
                                                      │ no             │
                                                      └──────► [HTTP risk]
 Behaviour risk ──────────────────────────────────────────────────┐
 Network risk ────────────────────────────────────────────────────┼─► [weighted-max] ► gateway policy
 Direct rule evidence ─────────────────────────────────────────────┘
```

The classical extractor normalises Unicode/whitespace, path encoding, query ordering, header/cookie ordering, then emits method and content-type one-hot fields plus request/path/query/body lengths, counts, percent-encoding density, suspicious-character density, token count, and Shannon entropy. The saved model metadata records feature version `http-classical-v1`.

Triage produces `BENIGN_LIKE` versus `SUSPICIOUS`. Its deployed early exit is disabled, so every request continues to the router. The router selects its top one family only when top probability is at least `0.90` and top-one margin is at least `0.40`; otherwise it selects its top two families. The selected family model emits class probabilities; HTTP risk is `1 - P(BENIGN)`.

The configured fusion strategy is `weighted_max_v1`. HTTP, behaviour, network, and each direct rule risk all have weight 1.0, so overall risk is their maximum. Evidence at or above 0.20 is included in the result; if none qualifies, the highest source is retained. The runtime does not currently load or invoke the saved soft-voting ensemble artifacts; `ensemble_used` remains false in the implemented pipeline.

### Deployed saved models

 

## 9. Threat categories and decisions

| Category | Objective / characteristic | Project signal and route |
| --- | --- | --- |
| SQL injection | Alter a database query through crafted input | Injection expert processes request-shape features such as query length, tokenisation, special-character and encoding density. |
| XSS | Cause script-like content to be handled or reflected by an application | Injection expert uses the same request representation but a separate target label. |
| Cookie injection | Alter state-bearing cookie input | Cookies are part of canonical request text; the injection expert has a dedicated label. |
| Directory traversal | Reach files outside the intended application path | Execution expert distinguishes this from injection labels using the request-shape feature vector. |
| Remote code execution | Cause execution-like input to reach a command/interpreter path | Execution expert supplies the dedicated label; low confidence can invoke deep adjudication. |
| Brute force | Repeated authentication attempts | Network model can emit `BRUTE_FORCE`; gateway counters login failures and applies temporary blocks after five failed login responses. |
| DoS/DDoS | High-rate or flow-level disruption | Network model has `DOS_DDOS`; gateway also load-sheds and rate-limits on local rolling counts. |
| Bot anomaly | Non-benign flow pattern in selected CICIDS labels | Network model emits `BOT_ANOMALY`, which participates as risk context. |

The gateway blocks when `overallRisk > blockRiskThreshold`, whose seeded/default value is 0.81. It returns `ALLOW` only by forwarding the request; it can independently return 429 rate-limit or 403 temporary block before calling the detection API. The offline policy simulator uses different inclusive bands (`<=0.20` allow, `<=0.50` monitor, `<=0.80` rate-limit, otherwise block), so it is an analysis utility rather than the gateway enforcement implementation.

```text
 request -> [temporary block?] --yes--> 403 temporary_block
                 | no
                 v
            [rate limit?] --yes--> 429 rate_limited
                 | no
                 v
      [model skipped/unavailable?] --yes--> forward + recorded mitigation
                 | no
                 v
      [overall risk > cached threshold?] --yes--> 403 waf_blocked + event
                 | no
                 v
      [deep pending?] --no--> forward normally
                 | yes
                 v
        forward provisionally -> revised non-benign risk >= .81?
                              ├─ yes -> block source 15 min (default)
                              └─ no  -> journal resolution only
```

## 10. Failure and fallback behaviour

```text
 gateway request -> Redis available in 250 ms?
                   ├─ no -> stateless NORMAL -> detection available in 5 s?
                   └─ yes -> mode permits inference?
                               ├─ no -> forward: INFERENCE_SKIPPED_UNDER_LOAD
                               └─ yes -> detection available in 5 s?
 detection unavailable -> forward: FAIL_OPEN_DETECTION_UNAVAILABLE
 detection available -> risk exceeds cached threshold? -> yes: 403; no: forward and journal
```

- Redis failure: the gateway logs the failure and processes the request statelessly. Network-context read errors also become empty context.
- Detection failure or timeout: the gateway records an unavailable verdict and forwards the request (fail open).
- Control-plane failure: the gateway retains its last policy cache; new policy updates are not fetched.
- RabbitMQ failure or local event queue saturation: the event is not persisted, but the request path continues.
- PostgreSQL/listener failure: the Rabbit listener throws, enabling the configured listener requeue behaviour; the gateway is not synchronously coupled to it.
- Missing/incompatible artifacts: detection startup preserves a load error and `/ready` / inference returns 503 rather than serving partial models.
- Flow schema error: the sensor returns 422; unavailable Redis returns 503.
- Deferred deep-worker error or full queue: the outcome is retained as failure or submission rejected; the original fast response is not reversed.

These are resilience/fallback paths, not evidence of high availability. In particular, the model and Redis outage behaviours intentionally favour upstream availability over detection enforcement.

## 11. Observed runtime characteristics

All figures below are saved artifacts, not measurements produced while writing this README. They use prepared/test data or a direct detection-service evaluation and should not be treated as gateway end-to-end production SLAs.

| Measurement | Observed value | Evidence and context |
| --- | ---: | --- |
| Balanced HTTP benchmark | 600 requests; p50 58.80 ms, p95 81.33 ms, p99 95.31 ms; 16.00 req/s | `artifacts/benchmarks/phase1-benchmark-v1/metrics.json`; 100 of each HTTP label through the offline pipeline. |
| Benchmark classification | attack recall 1.0; FPR 0.0; router accuracy 1.0 | Same benchmark artifact; all routes were fast-expert exits. |
| Saved phase-10 API evaluation | 30/30 API responses; p50 702.12 ms, p95 746.83 ms, p99 783.62 ms; 2.96 req/s | `artifacts/evaluations/phase10-summary.json`; direct HTTP calls with four workers. |
| Saved phase-10 detection | precision 1.0; recall 0.2; F1 0.3333; FPR 0.0 | Same artifact. It must be reported alongside its high false-negative rate (0.8), not as a general model score. |
| Deployed triage validation | macro F1 0.999912; p50 26.59 ms; p95 30.08 ms | Saved random-forest triage metrics. |
| Deployed router validation | top-1 accuracy/coverage 1.0; p50 1.29 ms; p95 1.49 ms | Saved logistic-router metrics, 31,134 train and 6,706 validation samples. |
| Deployed injection validation | macro F1 0.999771; p50 26.99 ms; p95 33.04 ms | Saved random-forest injection metrics. |
| Deployed execution validation | macro F1 1.0; p50 26.90 ms; p95 31.15 ms | Saved extra-trees execution metrics. |
| Deployed network validation | macro F1 0.999929; p50 26.86 ms; p95 31.37 ms | Saved network random-forest metrics. |
| Saved deep-model validation | macro F1 1.0; p50 4.19 ms; p95 5.08 ms | `distilbert-full-gpu-v1/metrics.json`; artifact does not establish live container CPU latency. |

Prepared ATRDF data records 216,814 train, 43,620 validation, and 55,868 test samples across six HTTP labels. Prepared CICIDS data records 2,201,270 train, 472,097 validation, and 472,358 test samples across four network labels. The CICIDS preparation manifest records 15,901 replacements each for non-finite `Flow Byts/s` and `Flow Pkts/s` values.

## 12. APIs and interfaces

| Method | Interface | Purpose |
| --- | --- | --- |
| GET | detection `/health`, `/ready`, `/v1/models`, `/v1/models/catalog` | Service liveness, readiness, loaded model versions/catalog. |
| POST | detection `/v1/detect`, `/v1/detect/batch` | Single or bounded batch HTTP classification. |
| POST | detection `/v1/network/detect` | Direct flow-feature classification. |
| GET | detection `/v1/corpus`, `/v1/corpus/{http|network}`, `/v1/escalations` | Saved replay corpus and in-memory deferred outcomes. |
| POST / GET | sensor `/v1/flows`, `/v1/network/recent` | Publish a classified flow and inspect recent sensor evidence. |
| GET/PUT/POST/PATCH/DELETE | control `/v1/control/*` | Authenticated policy, applications, blocks, models, feedback, audit, and lifecycle APIs. |
| GET | control `/v1/security/events`, `/statistics`, `/stream-ticket`, `/escalations` | Authenticated journal views/ticket and recent escalations. |
| WebSocket | control `/v1/stream/events?ticket=...` | Persisted event feed. |
| GET | control `/internal/v1/gateway-policy` | Unauthenticated internal policy snapshot used by gateway. |
| POST | control `/internal/v1/security/escalations` and `/internal/v1/training/*` | Internal deferred-verdict and adaptation lifecycle operations. |
| GET | gateway `/actuator/waf/policy`, `/actuator/waf/mode` | Cached policy and current load mode. |
| POST | adaptation `/v1/adaptation/curate`, `/runs`, `/drift` | Feedback export, candidate lifecycle registration, PSI result. |

Example direct detection payload (the direct API supports `rule_evidence`; the gateway does not populate it):

```json
{
  "method": "GET",
  "path": "/search",
  "query": "q=example",
  "headers": {"content-type": "application/json"},
  "cookies": {},
  "body": "",
  "source_ip": "203.0.113.10"
}
```

## 13. Configuration

| Setting | Default / source | Purpose |
| --- | --- | --- |
| `DETECTION_SERVICE_URL` | `http://127.0.0.1:8000` | Gateway target for HTTP detection. |
| `DETECTION_TIMEOUT` | `5s` | Gateway model call limit. |
| `DETECTION_MAX_BODY_BYTES` | `65536` | Largest request body inspected by gateway. |
| `WAF_BLOCK_RISK_THRESHOLD` | `0.81` | Fallback gateway threshold before a policy refresh. |
| `POLICY_REFRESH_INTERVAL` | `30s` | Control-policy cache refresh delay. |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | Redis connection for local processes. |
| `RABBITMQ_HOST` / `RABBITMQ_PORT` | `127.0.0.1` / `5672` | Broker connection for Java services. |
| `WAF_POSTGRES_URL` | local JDBC URL in control `application.yml` | Control-service data source. |
| `WAF_POSTGRES_USER`, `WAF_POSTGRES_PASSWORD` | Development configuration | PostgreSQL credentials; set externally and do not place real values in documentation. |
| `WAF_ADMIN_USERNAME`, `WAF_ADMIN_INITIAL_PASSWORD` | Development configuration | Bootstrap administrator; use a non-default secret outside local use. |
| `BEHAVIOUR_*`, `LOAD_MODE_*` | gateway `application.yml` | Windows, block duration, and mode thresholds. |
| `NETWORK_CONTEXT_KEY_PREFIX` / `NETWORK_CONTEXT_LOOKUP_TIMEOUT` | `waf:network:` / `25ms` | Sensor-to-gateway context lookup. |
| `SECURITY_EVENTS_ENABLED`, `SECURITY_EVENTS_EXCHANGE`, `SECURITY_EVENTS_QUEUE_CAPACITY` | `true`, `adaptive.waf.events`, `500` | Event-publisher operation. |

Model paths, selected algorithms, class lists, calibration methods, and detection thresholds are in `configs/models/*_deployment.toml` and `configs/models/pipeline.toml`. Dataset split settings live in `configs/data/*.toml`. Compose supplies the container-to-container hosts and exposes Redis 6379, RabbitMQ 5672/15672, PostgreSQL 55432, detection 8000, gateway 8080, control 8082, sensor 8083, adaptation 8084, dashboard 3000, and CRS 8090.

## 14. Running and verifying the project

### Prerequisites

- Docker Compose for the supplied all-in-one topology.
- For local Python execution: Python 3.11 or later, with the relevant `.[service]`, `.[deep]`, or `.[sensor]` extras.
- For local Java execution: Java 21 and Maven 3.9+ (the service POMs use Spring Boot 3.4.5).
- For dashboard development: Node/npm (the image uses Node 24; package metadata uses React 19, TypeScript, and Vite).

### Saved artifacts and data

The deployed detection image expects `artifacts/training` and `datasets/samples`; use the existing saved contents rather than retraining. Raw and processed datasets are needed only for preparation, offline benchmarking, or training scripts. The source repository ignores the large raw, processed, and artifact directories, so obtain them separately when cloning a fresh workspace.

### Compose topology

For a new local environment, the documented topology is:

```powershell
docker compose -f infra/docker/compose.yml up -d
```

This command is documented for setup; it was not run while producing this README. In an existing environment, use the already-running services and saved artifacts. The dashboard is available on `http://127.0.0.1:3000`; the gateway route is `http://127.0.0.1:8080/backend/...`.

### Verification

`scripts/smoke_platform.py` checks health, catalog/corpus availability, a direct detection batch, escalations, gateway enforcement, the journal, Redis, sensor flow processing, and control-plane surfaces. `scripts/verify_phase10.ps1` checks readiness then runs the phase-10 API evaluation; it changes the evaluation output file, so use it only when a new measurement is desired. `scripts/verify_phase10_failures.ps1` deliberately stops and restarts services/dependencies and is not a passive check.

## 15. Testing

Python tests under `tests/` cover contracts/configuration, request features, ATRDF/CICIDS preparation, pipeline/fusion/policy logic, model data loaders, router evaluation, network context, escalation worker, and detection-service behaviour. Java tests cover demo responses, gateway policy/mode/network snapshots, and control event sanitisation/consumption.

Typical commands are:

```powershell
# Python test suite (with the project environment already installed)
python -m pytest

# Java service tests
mvn -f gateway-service/pom.xml test
mvn -f security-control-service/pom.xml test
mvn -f demo-backend/pom.xml test
```

`scripts/benchmark_pipeline.py`, `scripts/evaluate_phase10.py`, and the `train_*.py` scripts produce or overwrite generated artifacts. They are intentionally not part of a normal verification run when preserving saved data.

## 16. Technology and design notes

| Layer | Technology | Role in this repository |
| --- | --- | --- |
| HTTP gateway | Spring Cloud Gateway / Reactor | Global request filtering and upstream proxying. |
| Control plane | Spring Boot, Spring Security, JPA/JDBC, Flyway | Authenticated operator APIs, event persistence, audit/schema migration. |
| Model serving | FastAPI, scikit-learn, joblib, PyTorch, Transformers | Saved classical/transformer model inference. |
| Behaviour state | Redis | Expiring counters, blocks, load mode and sensor context. |
| Messaging | RabbitMQ AMQP topic exchange | Decoupled gateway-to-journal event delivery. |
| Persistent store | PostgreSQL | Journal and control-plane durable records. |
| UI | React, TypeScript, Vite, Nginx | Operator dashboard and reverse-proxy boundary. |
| Infrastructure | Docker Compose | Local service topology. |

The code strongly supports these design choices: a model-service boundary keeps the gateway JVM independent of Python artifacts; RabbitMQ prevents PostgreSQL persistence from delaying a client response; Redis enables short windows and transient source state; and policy is cached to preserve a last-known enforcement threshold during control-plane outages. The repository also deliberately separates a network-flow classifier from HTTP request classification because they consume fundamentally different features.

## 17. Limitations

- The supplied Compose file has development defaults and publishes infrastructure ports locally; it is not a production deployment specification.
- The gateway fail-open path means detection, Redis, or model-service outages reduce enforcement rather than blocking all traffic.
- The gateway only routes the seeded demo backend; protected-application records are managed by the control plane but are not dynamically wired into Spring Gateway routes.
- The model artifacts show extremely high prepared-split scores, while the saved phase-10 direct API artifact reports recall 0.2. The repository does not provide external/holdout or production-traffic validation to reconcile these results.
- The saved deep metrics do not establish live CPU-container performance. The deep model container is configured to fall back to CPU.
- `rule_evidence` is accepted by the direct detection API but is not populated by the gateway’s request payload.
- Soft-voting ensemble artifacts and training candidate lifecycle records exist, but the deployed HTTP request path does not invoke an ensemble or automatically promote candidates.
- WebSocket origin patterns are unrestricted in code, while access is mediated by a short-lived ticket; additional browser-origin and transport hardening is not represented.
- Runtime observability consists of logs, health/status endpoints, persisted event timings, and saved reports; there is no metrics exporter or distributed tracing configuration.

## 18. Complete system diagram

```text
 ENTRY:  [HTTP client] ──► [optional CRS] ──► [Gateway filter] ──► [Demo backend]
                                             │       │
 DETECTION:                                  │       └──► [Detection API] -> [canonical/features]
 [Network sensor] -> [Network RF] -> [Redis] ◄────────────── [triage/router/experts] - -► [DistilBERT]
                                             │
 CONTROL:  [Gateway] - -AMQP- -► [RabbitMQ] - -► [Control] ──► [PostgreSQL]
                         [Detection] - -escalation- -► [Control] <──► [Redis]
 OPERATOR: [Dashboard] ──HTTP──► Gateway / Detection / Sensor / Adaptation ──► Control
            [Dashboard] ──ticketed WebSocket────────────────────────────────────► Control
```

# Technical implementation reference

This section is the code-to-runtime reference. A statement marked **fact** is directly represented by a source file, configuration file, migration, or saved artifact. A statement marked **limit** prevents a saved experiment or configuration capability from being mistaken for a live request-path behaviour.

## 19. Repository map and process entry points

```text
Adaptive Waf Ids/
├── configs/                         # data, model, threshold and service TOML
│   ├── core.toml                     # seed=641, paths, HTTP feature version
│   ├── pipeline.toml                 # triage/router/deep scheduling thresholds
│   ├── fusion.toml                   # weighted-max source weights
│   ├── deployment/                   # exact deployed artifact/run references
│   ├── training/                     # reproducible classical/deep settings
│   └── datasets/                     # ATRDF/CICIDS inputs and splits
├── src/adaptive_waf/
│   ├── contracts.py                  # validated request/result types and enums
│   ├── features/{canonical,classical}.py
│   ├── runtime/{artifacts,pipeline,fusion,network,policy}.py
│   ├── service/{app,runtime,escalation}.py
│   ├── data/                         # streaming readers and preparation
│   └── training/                     # loaders, estimators, calibration, deep training, benchmarks
├── gateway-service/src/main/java/... # reactive enforcement data plane
├── detection-service/Dockerfile      # serving image with saved Python artifacts
├── network-sensor/                   # packet/flow accumulator and Redis publisher
├── security-control-service/          # Flyway/JPA, AMQP, control and WebSocket
├── training-adaptation-service/       # feedback curation, PSI, candidate lifecycle client
├── demo-backend/                      # protected upstream target
├── dashboard/                         # React operator UI and Nginx proxy
├── infra/docker/compose.yml           # local topology; not executed here
└── datasets/ and artifacts/           # saved data and model evidence
```

| Process | Entrypoint / startup object | Long-lived state | Does not own |
|---|---|---|---|
| Gateway | `GatewayApplication` | reactive filter beans, Redis/WebClient clients, event executor | model objects/durable journal rows |
| Detection API | `adaptive_waf.service.app:create_app`; FastAPI lifespan | `RuntimeStore`, loaded pipeline/network model, escalation workers | enforcement response/Redis counters |
| Network sensor | `scripts.run_network_sensor` | flow accumulator, short TCP Redis client | HTTP model/SQL records |
| Control service | Spring Boot | JPA repositories, listener, WebSocket sessions, ticket map | gateway routing/Python models |
| Adaptation API | `scripts.run_training_adaptation_service` | outbound HTTP client/config | automatic retraining/promotion |
| Dashboard | Nginx-served React build | browser state and WebSocket | server-side credentials |

**Fact:** the detection Dockerfile copies `artifacts/training`; the sensor Dockerfile copies `artifacts/training/network`. This is saved-artifact packaging, not startup training.

## 20. Connection catalogue

| Source | Destination | Protocol/path | Payload/purpose | Wait/timeout | Failure | Code anchor |
|---|---|---|---|---|---|---|
| Client/CRS | Gateway | HTTP | protected request | request lifetime | HTTP failure | `AdaptiveDetectionFilter.filter(...)` |
| Gateway | Redis | reactive Redis | windows, blocks, load state, sensor evidence | network context 25 ms | empty/degraded context | `BehaviourService`, `RedisNetworkContextService` |
| Gateway | Detection | `POST /v1/detect` | safe headers, cookies, body, contexts | WebClient default 5 s | risk 0, forward fail-open | `DetectionClient`, `detectOrForward(...)` |
| Detection | Control | `POST /internal/v1/security/escalations` | deferred deep revision | background worker | original response remains decided | `ControlPlaneReporter` |
| Sensor | Redis | RESP `SET ... EX` | source network evidence JSON | socket 0.25 s | no enrichment until later successful write | `RedisNetworkContextStore` |
| Gateway | RabbitMQ | AMQP `adaptive.waf.events` | security journal event | local bounded executor | log/drop if broker publish fails | `SecurityEventPublisher` |
| RabbitMQ | Control | durable `security.events.persist`; `security.#` | journal event | listener transaction | error reaches configured requeue | `SecurityEventConsumer.consume(...)` |
| Control | PostgreSQL | JDBC/JPA | events/policy/apps/models/feedback/audit | Spring transaction | DB rollback only | control services |
| Dashboard | all services | Nginx HTTP/WebSocket proxies | operator APIs/live events | browser lifetime | unavailable UI state | `dashboard/nginx.conf` |

```text
 [Client] ──HTTP──► [Gateway] ──sync POST /v1/detect──► [FastAPI detection]
                       │  └──sync reads/writes──► [Redis] ◄── SET EX evidence ── [Sensor]
                       └──async AMQP──► [RabbitMQ] - -durable- -► [Control] ──JPA──► [PostgreSQL]
 [Detection] - -deferred revision- -► [Control] ◄──HTTP/WebSocket── [Dashboard]
 [Dashboard] ──proxied HTTP──► [Gateway]
```

Solid arrows are request-time calls; dashed arrows can happen after the caller has received a response. The journal path is not an enforcement transaction.

## 21. Gateway internal lifecycle

**Primary code:** `gateway-service/src/main/java/.../filter/AdaptiveDetectionFilter.java`. `GatewayApplication` enables detection, policy, behaviour, events, network and load-mode properties. The demo route is `/backend/**` with one segment stripped. Filter order is `HIGHEST_PRECEDENCE + 100`; actuator paths bypass it.

```text
 exchange -> actuator? ─yes─> bypass chain
              | no
              v
 request ID -> cacheSafeBody -> loadMode.recordRequest (250 ms) -> temporary block? ─yes─> 403
                                                                    | no
                                                                    v
 observe source -> rate limit? ─yes─> 429
                   | no
                   v
 mode permits inference? ─no─> forward: INFERENCE_SKIPPED_UNDER_LOAD
             | yes
             v
 network context (<=25 ms) + DetectionClient -> risk > policy? ─yes─> publish attack; 403
                                                     | no
                                                     v
                                     forward; beforeCommit publish allow
             any client error ────────────────────────────────────► forward FAIL_OPEN_DETECTION_UNAVAILABLE
```

| Method | Inputs / output | State/dependency | Implementation effect |
|---|---|---|---|
| `filter(...)` | `ServerWebExchange`, chain -> `Mono<Void>` | Reactor | bypasses actuator, ID mutation, body replay, decision sequence |
| `cacheSafeBody(...)` | exchange -> decorated exchange | `DataBuffer` | unknown/oversize body becomes `""`; otherwise joins/releases buffer and makes it re-readable |
| `process(...)` | enriched context -> `Mono<Void>` | behaviour service | source-block check, source observation, rate limit precede ML |
| `detectOrForward(...)` | detection DTO/context -> chain | network Redis, WebClient, cached policy | inference only NORMAL/ELEVATED; strict `>` threshold; error forwards |
| `toDetectionRequest(...)` | exchange -> DTO | request content | removes Authorization, Cookie, X-Request-ID, Host, Connection, Accept, Accept-Encoding, User-Agent, Content-Length, Transfer-Encoding; cookies sent separately |
| `forwardAndRecord(...)` | exchange/verdict -> `Mono<Void>` | Rabbit publisher | emits allow event in `beforeCommit`; errors swallowed/logged |

Source for the detection DTO is first `X-Forwarded-For`, else remote address. Behaviour/network Redis construction uses remote-address source with colons replaced, so proxy deployments can produce different model and behaviour identities.

```text
if actuator: forward
id = X-Request-ID or UUID; retain/replay small body
mode = loadMode.recordRequest() within 250 ms
if temporarily blocked: 403
observe source; if rate limited: 429
if mode disallows inference: forward with zero-risk mitigation
network = Redis context (empty on error/25 ms timeout)
try POST detection; catch -> forward fail-open
if overallRisk > cached policy threshold: publish attack; 403
else forward and publish allow before response commit
```

## 22. Redis: exact cross-service state

| Key pattern | Type / operation | Writer -> reader | TTL / lifecycle | Meaning |
|---|---|---|---|---|
| `waf:network:{source}` | string; `SET value EX 300` | sensor -> gateway | 300 s in `network_sensor.toml` | risk/class/confidence/version/time JSON |
| behaviour request windows | sorted set; add timestamp, range-prune, count | gateway -> gateway | configured short/medium window | source request rate |
| source/endpoint window | sorted set | gateway -> gateway | configured rolling window | hot-endpoint rate |
| login failures | increment/expiry | gateway -> gateway | configured expiry | failed upstream authentication count |
| attack state | increment/expiry | gateway -> gateway | configured expiry | prior attack/block context |
| temporary source block | string | gateway/control -> gateway | configured duration | pre-model 403 condition |
| load mode state | string/counter | gateway -> gateway | config controlled | NORMAL/ELEVATED/DEGRADED/EMERGENCY state |

Only `waf:network:{source}` is an independently traceable literal shared by two services: `network_sensor/redis_store.py` writes it and `RedisNetworkContextService` reads it. Other rows are gateway state families; this documentation does not invent literals absent from the inspected cross-service contract.

```text
 [request] -> [rolling windows: add timestamp, prune expired] -> [behaviour payload]
      |                                                           |
      +-> [temporary source block exists] -> [403]               +-> [detection payload]
      +-> [GET sensor evidence] --invalid/absent--> [empty network context] -^
```

Redis errors are not security-deny errors. Missing/invalid sensor evidence becomes no network context; model-service failure lets an otherwise permitted request continue. That is the implemented availability trade-off.

## 23. Canonical HTTP representation and the exact 24-feature vector

`src/adaptive_waf/features/canonical.py` owns both the deep-model text form and the normalization reused by classical measurements. `_normalize_text` applies Unicode NFC, turns CRLF into LF, collapses every whitespace run to one ASCII space, then strips. `_normalize_path` normalizes, `unquote`s once, then `quote`s with `/%:@-._~!$&'()*+,;=` safe; an empty result is `/`. `_normalize_query` calls `parse_qsl(..., keep_blank_values=True)`, sorts `(name,value)` pairs, then `urlencode`s them. Header names are normalized/lower-cased and sorted; cookie names retain case and are sorted.

`serialize_deep_request(request)` emits six double-newline-separated sections in this exact order: `[METHOD]`, `[PATH]`, `[QUERY]`, `[HEADERS]`, `[COOKIES]`, `[BODY]`. Header lines use `name: value`; cookies use `name=value`; this function does not truncate. `normalized_request_text` instead joins normalized path, query, **header values only**, cookie values only, and body by newline. It is the text used by several classical measurements.

```text
 [HttpRequestRecord] -> [canonical.py] -> [six-section canonical text] -> [DistilBERT tokenizer]
                                      └-> [normalized request text] -> [24 ordered floats] -> [fast models]
```

Example consistent with the functions: raw path `/a/%2e%2e/b`, query `z=2&a=`, and header `X T: a\r\n b` becomes canonical path `/a/../b`, query `a=&z=2`, header name `x t`, header value `a b`. Canonicalization reduces superficial ordering/encoding variance; it does not remove the raw percent-encoding evidence used by features 21--22.

All values emitted by `ClassicalFeatureExtractor.extract(...)` are Python `float`. Insertion order below is the feature contract (`http-classical-v1`); runtime wraps the `(24,)` row for scikit-learn. Preparation/training loaders preserve this order, so artifact compatibility is not inferred from incoming JSON order.

| # | Feature | Exact extraction | Edge behaviour / meaning |
|---:|---|---|---|
| 1 | `method_get` | 1.0 when normalized uppercase method is GET | otherwise 0 |
| 2 | `method_post` | same for POST | otherwise 0 |
| 3 | `method_put` | same for PUT | otherwise 0 |
| 4 | `method_patch` | same for PATCH | otherwise 0 |
| 5 | `method_delete` | same for DELETE | otherwise 0 |
| 6 | `method_other` | 1.0 if none of the five methods matches | uncommon verb bucket |
| 7 | `content_type_application_json` | first case-insensitive Content-Type, lower/split `;`, equality | one-hot |
| 8 | `content_type_application_x_www_form_urlencoded` | same | one-hot |
| 9 | `content_type_multipart_form_data` | same | one-hot |
| 10 | `content_type_text_plain` | same | one-hot |
| 11 | `content_type_other` | no listed type matches | includes missing content type |
| 12 | `request_length` | `len(normalized_request_text)` | canonical path/query/values/body text |
| 13 | `path_length` | `len(normalized_path)` | decoded/re-encoded path |
| 14 | `path_depth` | non-empty `/` components | `/` is 0 |
| 15 | `query_length` | `len(normalized_query)` | sorted/re-encoded query |
| 16 | `body_length` | `len(request.body)` | original body string, not canonical text |
| 17 | `header_count` | header mapping item count | model sees gateway-safe headers |
| 18 | `cookie_count` | cookie mapping item count | cookies are DTO-separate |
| 19 | `parameter_count` | query fragments split on `&` that contain `=` | blank query is 0 |
| 20 | `token_count` | `[A-Za-z0-9_]+` matches in normalized request text | lexical, not WordPiece count |
| 21 | `percent_encoded_count` | `%[0-9A-Fa-f]{2}` matches in raw path+query+body | raw encoding evidence retained |
| 22 | `percent_encoded_density` | count / raw joined input length | 0 for empty raw input |
| 23 | `special_character_density` | count of `'\"<>;|&$`(){}[]\\` in normalized text / length | 0 for empty text |
| 24 | `shannon_entropy` | `-Σ p(c) log2 p(c)` over normalized-text characters | 0 for empty text |

These are request-shape and lexical indicators. The implementation does not claim that any individual feature proves SQLi, XSS, traversal, or RCE.

## 24. Hierarchical HTTP inference: objects, probabilities and risk

```text
 [24 floats] -> [calibrated RF triage] -> [calibrated logistic router]
                    (early exit disabled)       |
                        p1>=.90 AND p1-p2>=.40? ├─ yes -> one family
                                                 └─ no  -> both families
                                                           |
                                              [Injection RF] / [Execution ET]
                                                           |
                                           confidence < .90? ─ no -> [weighted-max fusion]
                                                | yes
                                                +--inline--> [DistilBERT] -> fusion
                                                +--async---> [queue] - -later- -> [DistilBERT]
```

`AdaptiveDetectionPipeline.detect(...)` extracts the vector once, calls triage, then uses `select_experts`. Let `p1` and `p2` be the highest and second-highest router probabilities. Exactly one family is selected iff `p1 >= 0.90` **and** `p1 - p2 >= 0.40`; otherwise the ranked top two are invoked. This avoids a confident-but-ambiguous router choosing only one specialist. An expert result has `attack = argmax(probabilities)`, `confidence = max(probabilities)`, and `risk = 1 - P(BENIGN)`. The highest-risk specialist is the fast HTTP verdict.

| Runtime model | Saved/deployed artifact | Input / labels | Algorithm and recoverable settings | Calibration / runtime status |
|---|---|---|---|---|
| Triage | `triage-full-v1/random_forest/model.joblib` | 24 floats; `BENIGN_LIKE`, `SUSPICIOUS` | `RandomForestClassifier`; 300 trees, `min_samples_leaf=2`, class weight `balanced_subsample`, seed 641 | isotonic artifact `calibration-full-v1/triage/isotonic/model.joblib`; loaded and called |
| Router | `router-full-v1/logistic_regression/model.joblib` | 24 floats; INJECTION/EXECUTION family | scaled logistic regression, C=1, balanced classes, max_iter=1000; training wrapper uses sigmoid CV=3 calibration | loaded and called; its output controls specialist fan-out |
| Injection | `injection-expert-full-v1/random_forest/model.joblib` | 24 floats; BENIGN, SQL_INJECTION, XSS, COOKIE_INJECTION | RF 250 trees, min leaf 2, balanced-sub-sample class weight, seed 641 | isotonic calibrated artifact loaded and called |
| Execution | `execution-expert-full-v1/extra_trees/model.joblib` | 24 floats; BENIGN, DIRECTORY_TRAVERSAL, REMOTE_CODE_EXECUTION | ExtraTrees 250 trees, min leaf 2, balanced-sub-sample class weight, seed 641 | isotonic calibrated artifact loaded and called |
| Deep | `distilbert-full-gpu-v1` | six-section canonical text; six attack labels | Hugging Face `distilbert-base-uncased`, maximum sequence length 256 | temperature JSON, loaded lazily/called only for low-confidence escalation |

### What “calibrated” means here

Classical forest leaf vote averages can be highly discriminative yet poorly aligned with empirical likelihood. The calibration scripts fit an isotonic monotonic mapping on validation predictions, then serialise the calibrated estimator with joblib. A raw probability `p` is transformed by this learned non-decreasing mapping before downstream risk/threshold logic; it is not merely a display adjustment. For the router, the runner wraps the base estimator in `CalibratedClassifierCV(method="sigmoid", cv=3)`.

**Limit:** generic tree defaults such as split criterion/max depth are not overridden in the inspected training configuration, so this README records the explicit settings above rather than pretending an artifact metadata report established every inherited scikit-learn default. Soft-voting ensemble code/artifacts are evaluated by training tooling but are not invoked by `AdaptiveDetectionPipeline`.

## 25. DistilBERT loading, inference and deferred adjudication

`runtime/artifacts.py:DistilBertPredictor` uses a lock for lazy one-time loading. It resolves requested `cuda` to CPU when `torch.cuda.is_available()` is false, uses `AutoTokenizer.from_pretrained` and `AutoModelForSequenceClassification.from_pretrained` from the saved artifact, moves model to device, then calls `eval()`. On inference it tokenizes canonical text with truncation, padding and `max_length=256`, builds PyTorch tensors, obtains classification logits, divides them by saved temperature, then softmaxes. Predicted class is the maximum probability; deep HTTP risk is `1 - P(BENIGN)`.

The saved training code uses the base `distilbert-base-uncased`, six labels, `AdamW`, learning rate `2e-5`, two epochs, batch size 16 and maximum length 256. A separate char-CNN candidate is configured (four epochs, batch 128, LR .001, 48-dim embeddings, 64 filters, dropout .2), but the deployed runtime path is DistilBERT, not char-CNN. The training code does not configure a learning-rate scheduler.

```text
 Gateway ──sync request──► Fast models ──provisional + deepPending──► Gateway
 Gateway ──► client/upstream decision is already complete
 Fast models ──non-blocking, confidence < .90──► bounded EscalationWorker queue
 queue ──daemon worker──► DistilBERT ──revised POST──► Control service
                                                        └──► optional future source block
```

`EscalationWorker` owns a `Queue(maxsize=256)`, two daemon worker threads, a lock-protected outcome deque limited to 200, and submitted/resolved/rejected/failed counters. Jobs contain escalation UUID, request, provisional result and enqueue time. `submit` is non-blocking; a full queue increments rejected and returns false. Worker exceptions are caught and retained as failures. A callback failure is likewise recorded; it cannot undo the original forward/block response. In `EscalationController`, a revised non-benign result with risk at least `.81` can create a 15-minute source block when the corresponding auto-block setting is enabled. This is future-request mitigation, not rollback.

## 26. Fusion and explicit non-ML signals

`runtime/fusion.py` validates the four source weights and combines `http`, `behaviour`, `network`, and `rule` risks. The configured strategy is `weighted_max_v1` and all default weights are 1.0. For signals `r_s` and weights `w_s`:

```text
weighted(s) = w_s * r_s
overallRisk = max(weighted(http), weighted(behaviour), weighted(network), weighted(rule evidence...))
```

Rule evidence is expanded to `rule:{name}`. Evidence whose weighted score is at least 0.2 is supporting evidence; when none reaches 0.2, fusion retains the maximum contributor so output is not evidence-free. Behaviour and network context default to risk 0 when absent. Example: HTTP .62, behaviour .20, network .87, and rule `.10` yield .87 with default weights, and network is supporting evidence.

The offline policy simulator is deliberately separate from live gateway enforcement: `policy.toml` maps risk `<=.20` to allow, `<=.50` monitor, `<=.80` rate-limit and above to block. Gateway enforcement instead uses its cached control-plane threshold and strict greater-than comparison.

## 27. Detection API contract, lifecycle and concurrency

`service/app.py` defines Pydantic input types and FastAPI endpoints. A middleware uses a supplied `X-Request-ID` or generates UUID, echoes it on the response, and the lifespan calls `RuntimeStore.start()`.

| Endpoint | Input / output | Error boundary |
|---|---|---|
| `GET /health` | liveness | normal HTTP status |
| `GET /ready` | loaded-model readiness | 503 when store not ready |
| `POST /v1/detect` | `DetectPayload` -> detection/risk/version/evidence/stage-latency object | unavailable artifact 503, inference timeout 504, validation/value error 422 |
| `POST /v1/detect/batch` | up to 100 requests plus optional labels | same per batch runtime failure boundary |
| `POST /v1/network/detect` | `features: dict[str,float]` -> network context | strict feature schema failure is validation/value error |
| `GET /v1/models`, `/v1/models/catalog` | deployed versions/catalog | read-only |
| `GET /v1/corpus`, `/v1/corpus/{kind}` | sample corpus, limit 1..500 | read-only |
| `GET /v1/escalations`, `/statistics` | retained worker outcomes/counters | in-memory, capped outcomes |

`DetectPayload` has method default `GET`, required path, query/header/cookie/body fields, optional `source_ip` and UUID request ID, optional `BehaviourPayload` (risk plus short/medium request count, failed auth, previous attacks), optional `NetworkPayload`, and `rule_evidence`. `RuntimeStore` loads models once, retains them in memory and serializes detection calls with an `RLock`; this protects inference object access but becomes a throughput bottleneck under one process. Deep work is deliberately outside that request lock through its own bounded queue. The network wrapper rejects missing/unexpected manifest features and non-finite floats before `predict_proba`.

## 28. Network IDS: packet flow to fusion input

`network_sensor/flows.py:FlowAccumulator` converts packet observations into the CICIDS-compatible row consumed by `runtime/network.py`. A flow tracks forward/backward direction by the original tuple, timestamps, bytes, flags, initial-window values and gaps. Duration is microseconds with a lower bound of one microsecond. `NetworkSensor.process(...)` normalizes source IP with `ipaddress`, calls the network detector, builds `NetworkEvidence`, and writes it to Redis. The gateway reads the evidence later; it does not synchronously invoke the sensor.

```text
 [packet observations] -> [FlowAccumulator] -> [ordered 38 numeric values]
       -> [network RF predict_proba] -> [NetworkEvidence: class/confidence/risk]
       -> [Redis EX 300] -> [gateway context lookup] -> [weighted-max fusion]
```

| # | CICIDS-compatible feature | Live computation / unit |
|---:|---|---|
| 1 | `Dst Port` | destination transport port |
| 2 | `Protocol` | packet protocol number |
| 3 | `Flow Duration` | last-first timestamp in microseconds, minimum 1 |
| 4 | `Tot Fwd Pkts` | forward packet count |
| 5 | `Tot Bwd Pkts` | backward packet count |
| 6 | `TotLen Fwd Pkts` | sum forward packet bytes |
| 7 | `TotLen Bwd Pkts` | sum backward packet bytes |
| 8 | `Fwd Pkt Len Max` | maximum forward packet byte length |
| 9 | `Fwd Pkt Len Mean` | population mean forward packet byte length |
| 10 | `Fwd Pkt Len Std` | population standard deviation forward length |
| 11 | `Bwd Pkt Len Max` | maximum backward packet byte length |
| 12 | `Bwd Pkt Len Mean` | population mean backward length |
| 13 | `Bwd Pkt Len Std` | population standard deviation backward length |
| 14 | `Flow Byts/s` | total bytes / duration seconds |
| 15 | `Flow Pkts/s` | total packets / duration seconds |
| 16 | `Flow IAT Mean` | mean inter-arrival time, microseconds |
| 17 | `Flow IAT Std` | population stddev inter-arrival time, microseconds |
| 18 | `Flow IAT Max` | largest inter-arrival time, microseconds |
| 19 | `Flow IAT Min` | smallest inter-arrival time, microseconds |
| 20 | `SYN Flag Cnt` | packets whose flags include SYN |
| 21 | `RST Flag Cnt` | packets whose flags include RST |
| 22 | `PSH Flag Cnt` | packets whose flags include PSH |
| 23 | `ACK Flag Cnt` | packets whose flags include ACK |
| 24 | `Pkt Len Min` | minimum all-direction packet byte length |
| 25 | `Pkt Len Max` | maximum all-direction packet byte length |
| 26 | `Pkt Len Mean` | mean all-direction packet byte length |
| 27 | `Pkt Len Std` | population stddev all-direction packet length |
| 28 | `Down/Up Ratio` | backward count / `max(1, forward count)` |
| 29 | `Init Fwd Win Byts` | first forward direction TCP window value |
| 30 | `Init Bwd Win Byts` | first backward direction TCP window value |
| 31 | `Active Mean` | mean active-period duration in microseconds |
| 32 | `Active Std` | population stddev active period |
| 33 | `Active Max` | max active period |
| 34 | `Active Min` | min active period |
| 35 | `Idle Mean` | mean gap exceeding one second, microseconds |
| 36 | `Idle Std` | population stddev of those gaps |
| 37 | `Idle Max` | maximum such gap |
| 38 | `Idle Min` | minimum such gap |

The deployed `network-full-v1` is a 250-tree Random Forest (`min_samples_leaf=2`, balanced-subsample class weighting, seed 641) stored as joblib with a feature manifest. `OfflineNetworkDetector` requires exactly those manifest names/order and finite float values. It calculates `risk = 1 - P(BENIGN)` and returns maximum-probability `NetworkClass`/confidence. CICIDS preparation replaces non-finite `Flow Byts/s`/`Flow Pkts/s` values with `0.0` (saved manifest reports 15,901 replacements), maps `Benign` -> BENIGN, FTP-BruteForce/SSH-Bruteforce -> BRUTE_FORCE, GoldenEye/Slowloris -> DOS_DDOS, and Bot -> BOT_ANOMALY. Thus network classification is a flow model, not an HTTP request classifier; the live feature set is a best-effort accumulator, not proof of full raw-CICIDS capture parity.

## 29. RabbitMQ, durable journal and PostgreSQL transaction boundaries

`RabbitTopology` declares durable topic exchange `adaptive.waf.events`, durable queue `security.events.persist`, and binding `security.#`. Gateway `SecurityEventPublisher` submits `RabbitTemplate.convertAndSend(...)` to a thread-pool executor (core 1, max 2, queue 500, `DiscardPolicy`); broker/serialization errors are logged and dropped rather than blocking a gateway response.

```text
 Gateway - -async security.request/security.attack- -> [AMQP exchange]
 [AMQP exchange] - -routing key security.#- -> [durable queue] -> [SecurityEventConsumer]
 [SecurityEventConsumer] -> [sanitize + de-duplicate eventId] -> [PostgreSQL @Transactional save]
                                                        -> [WebSocket sessions broadcast]
```

`SecurityEventConsumer.consume(...)` is `@Transactional`. It ignores duplicate event IDs, maps selected fields to `PersistedSecurityEvent`, computes confidence (deep first; otherwise expert maximum; otherwise triage), recursively redacts JSON keys containing authorization/password/token/secret/api_key/apikey, caps JSON at 32,768 characters, saves, then broadcasts. Invalid input/error is thrown to listener infrastructure; it is not silently acknowledged. Flyway migrations V1--V4 create/evolve the journal, including detailed event fields and indexes.

| Service/method family | Transactional DB work | Non-transactional interaction / implication |
|---|---|---|
| `SecurityEventConsumer.consume(...)` | persisted security event and duplicate check | AMQP delivery and WebSocket broadcast are outside one ACID unit |
| `ControlPlaneService.updatePolicy/createApplication/setApplicationEnabled` | application/policy state plus audit rows | gateway sees change only at later refresh |
| `ControlPlaneService.block/unblock` | durable block/audit record | Redis side effect is not rolled back if later DB work fails |
| `ControlPlaneService.registerModel/promote/assignModel/submitFeedback` | lifecycle/assignment/feedback plus audit | no model file move or Python hot reload is implied |
| `TrainingLifecycleService.createRun/completeRun/registerCandidate/evaluate/approve/retire` | training-run/candidate/evaluation lifecycle rows | metadata lifecycle only |

This gives a precise distinction: Gateway -> RabbitMQ -> Control -> PostgreSQL is a distributed, asynchronous chain, not one ACID request. A client can receive the upstream response before event persistence, or persistence can never occur if the local event executor discards work/broker delivery fails.

### Control-plane tables and ownership

Flyway supplies journal and control schema. Important durable relationships are: `security_events` is the event journal; `admin_users` supplies BCrypt-backed principals; applications own policy/model assignments; policies/versions and audit records preserve control changes; training runs, candidates, evaluations and feedback preserve lifecycle evidence. `PersistedSecurityEvent` stores event identity/time, request identity/source/method/path, verdict/attack/risk/confidence, route/model/evidence JSON and outcome-oriented fields. Redis holds transient blocks/windows/evidence; joblib/Hugging Face directories hold artifacts; the in-memory escalation deque and ticket map are lost on process restart.

## 30. Control authentication and live events

`SecurityConfiguration` disables CSRF, permits actuator health/info, `/internal/**`, and `/v1/stream/**`, requires `ROLE_ADMIN` elsewhere, and enables HTTP Basic. Bootstrap admin insertion is idempotent (`ON CONFLICT DO NOTHING`) and passwords are BCrypt-hashed. **Limit:** internal endpoints are public at the Spring Security layer; deployment/network isolation must provide any additional trust boundary represented outside this code.

```text
 Dashboard --Basic-auth GET stream-ticket--> Control API -> StreamTicketService.issue
 Dashboard <-- UUID ticket + expiry/path ----------- Control API
 Dashboard -- WebSocket ?ticket=... --> endpoint --isValid--> ticket map
 Dashboard <-- accepted connection + event frames -- endpoint (present and unexpired only)
```

`StreamTicketService` keeps tickets in a `ConcurrentHashMap`; `issue` purges expired entries and grants ten minutes. `isValid` rejects blank/missing/expired tickets but does **not** remove a valid one. Tickets therefore remain reusable until expiry and are process-local. `WebSocketConfiguration` allows all origin patterns and its handshake interceptor only checks this query ticket. `SecurityEventBroadcaster` maintains a `CopyOnWriteArraySet` of sessions, synchronizes individual sends, emits connected/pong frames, and removes broken sessions. Dashboard `useEventStream` first obtains the ticket and then connects through `/control-ws/`.

## 31. Policy cache, adaptation and dashboard boundaries

Gateway `GatewayPolicy` refreshes at startup and on schedule by a blocking `WebClient` call using its refresh interval, retaining the last known policy if refresh fails. `OperatingMode` permits ML only in NORMAL/ELEVATED; DEGRADED/EMERGENCY skips inference. The gateway uses `risk > threshold`, so equality does not block.

`training-adaptation-service` is lifecycle tooling, not a trainer. It retrieves internal feedback, writes curated JSONL containing sanitised metadata (event/version/verdict/correct type/method/path/original prediction/submission time), creates/updates training run/candidate/evaluation state via control APIs, and reports challenger/shadow-style metadata without automatic promotion. Its PSI routine bins values across reference min/max, floors shares at `1e-6`, and sums `(current-reference) * ln(current/reference)`; `<.10` is stable, `<.25` monitor, otherwise shadow recommendation. It does not retrain a model in the runtime API.

Dashboard Nginx maps `/control-api/` to control (hiding `WWW-Authenticate`), `/control-ws/` to upgrade-capable control WebSocket with 3600 s read timeout, `/gateway-api/` to gateway, and analogous detection/sensor/adaptation proxies. React `DashboardApi` sends Basic credentials held in UI state via `btoa`; `Generator` can read sample corpus and send a request through gateway, while `InfrastructurePanel` polls infrastructure every two seconds. No browser action was invoked to write this documentation.

## 32. End-to-end paths and failure matrix

```text
 Client -> AdaptiveDetectionFilter -> Redis (block/window/network) -> RuntimeStore/Pipeline
                                                  canonicalize -> vector -> triage/router/expert -> fuse
                                  ┌── risk > threshold ──► client 403; async security.attack -> RabbitMQ
                                  └── otherwise ─────────► Demo backend -> upstream response -> client
                                                                  └─ beforeCommit security.request -> RabbitMQ
 RabbitMQ - -durable consumer transaction- -> Control service -> PostgreSQL
```

| Condition | Direct code path | What continues / what is lost |
|---|---|---|
| Redis unavailable/invalid sensor evidence | behaviour/network helper returns degraded or empty context | request can continue; behavioural/network contribution lost |
| Detection unavailable, timeout or model loading failed | gateway catches client error -> `FAIL_OPEN_DETECTION_UNAVAILABLE`; API itself reports 503/504 | upstream may receive request; ML enforcement lost |
| deep queue full | `submit` returns false, increments rejected | fast verdict remains; no delayed revision |
| deep callback/control unavailable | worker retains failure | no future source-block action from that revision |
| RabbitMQ publish unavailable/executor saturated | publisher logs/drops | client response/enforcement unaffected; journal event absent |
| PostgreSQL/control consumer failure | listener exception/requeue path | persistence/live event delayed; gateway already responded |
| sensor unavailable | no fresh `waf:network:*` string | fusion uses network risk 0/available other signals |

## 33. Saved runtime evidence and what it does not prove

| Evidence file | Path/sample/execution | Recorded result | Careful reading |
|---|---|---|---|
| Phase-1 benchmark | `artifacts/benchmarks/phase1-benchmark-v1/metrics.json`; 600 balanced prepared test requests | 600 correct; p50 58.80 ms, p95 81.33 ms, p99 95.31 ms, 16.00 req/s; 100 allow/500 block; no deep/ensemble exits | offline pipeline benchmark, not full gateway+broker+database latency |
| Smoke benchmark | `artifacts/benchmarks/smoke-phase1-benchmark-v1/metrics.json`; 6 requests | p50 about 96.03 ms | very small smoke evidence |
| Phase-10 API | `artifacts/evaluations/phase10-summary.json`; 30 direct API requests (six scenarios x10; workers=4) | p50 702.12 ms, p95 746.83 ms, p99 783.62 ms, 2.96 req/s; precision 1, recall .2, F1 .333, FPR 0, FNR .8 | direct detection API scenario test, not a complete gateway E2E measurement |
| Model artifacts | deployed model `metrics.json` and calibration evidence | saved validation metrics are near/perfect for listed prepared splits; network macro F1 .999929; deep saved validation/test metrics perfect | cannot reconcile generalisation with phase-10 low recall from repository alone |

The apparently contradictory prepared-split scores and phase-10 recall are both documented rather than averaged away. Saved files establish different sample selection/execution paths, but do not establish a causal root cause such as distribution shift, fixture semantics, or environment. The repository contains no production traffic trace or independent external holdout sufficient to resolve it.

## 34. Data preparation, training and artifact-load chain

HTTP preparation streams ATRDF JSON using `ijson`, parses URL/header/cookie input and maps attack aliases into the six runtime attack classes. `data/preparation.py` makes a deterministic group key from canonical deep text after replacing numeric tokens with `<NUMBER>` and long (16+ character) alphanumeric/underscore/hyphen tokens with `<TOKEN>`, then hashes it with SHA-256. The first eight hash bytes of `seed:group` select the configured 70/15/15 split. This prevents near-duplicate canonical requests leaking across splits. Triage turns BENIGN into `BENIGN_LIKE` and all others into `SUSPICIOUS`; router excludes benign and maps SQL/XSS/Cookie to INJECTION and traversal/RCE to EXECUTION; specialists filter their own allowed classes.

```text
 [ATRDF streaming JSON] -> [canonical-group split] -> [HTTP train/val/test JSONL]
                                                            ├-> [classical fit + validation calibration] -> [joblib/metrics/TOML]
                                                            └-> [DistilBERT fine-tuning] -> [save_pretrained/temperature]
 [CICIDS CSV] -> [38-column finite preparation] -> [network JSONL] -> [network RF fit] -> [joblib/metrics/TOML]
 joblib + saved Transformers -> [runtime load_artifacts] -> [one RuntimeStore model set]
```

The saved ATRDF manifest records train/validation/test counts 216,814 / 43,620 / 55,868. CICIDS v3 records 2,201,270 / 472,097 / 472,358. Model runners create Logistic Regression with `StandardScaler`, random forests/ExtraTrees with `n_jobs=-1`, dump with joblib, then write metric JSON. Calibration uses validation predictions and evaluates against test data. The runtime does **not** run these stages.

```text
 FastAPI lifespan -> RuntimeStore.start -> load_adaptive_pipeline -> resolve deployment TOML
                                                        -> joblib: calibrated triage/router/experts
                                                        -> reusable pipeline + versions -> RuntimeStore
 RuntimeStore -> bind/start escalation workers; deep predictor remains lazily loaded under lock on first use
```

Artifacts are saved and deployed by configuration selection. They are not dynamically fetched from PostgreSQL/RabbitMQ, and a control-plane model assignment alone does not hot-swap the Python in-memory objects.

## 35. Database relationship sketch and ownership boundary

```text
 [ADMIN_USERS] 1 ──< [AUDIT_LOG]
 [APPLICATIONS] 1 ──< [POLICY_ASSIGNMENTS]       [POLICIES] 1 ──< [POLICY_VERSIONS]
 [APPLICATIONS] 1 ──< [MODEL_ASSIGNMENTS]
 [TRAINING_RUNS] 1 ──< [MODEL_CANDIDATES] 1 ──< [MODEL_EVALUATIONS]
 [SECURITY_EVENTS] -- context when available --> [APPLICATIONS]
 [SECURITY_EVENTS]: event_id (PK), occurred_at, source_ip, method, path, attack, overall_risk
```

The ER diagram is a relationship-oriented summary of Flyway V1--V4, not a substitute for migration DDL. `security_events` is authoritative for durable journal history; model artifacts are files in `artifacts/`; policy/application/lifecycle entities are authoritative in PostgreSQL; Redis owns only temporary behavioural/network/block state. The control service writes application, policy, model, feedback and audit state through `ControlPlaneService`; `TrainingLifecycleService` owns run/candidate/evaluation state. The dashboard reads those APIs rather than direct database connections.

## 36. Final runtime topology and explicit limitations

```text
 DATA PLANE:      [Client / optional CRS] -> [Spring Cloud Gateway] -> [Demo backend]
                                                <-> [Redis transient state]
 DETECTION PLANE: [Gateway] -> [FastAPI RuntimeStore] -> [classical triage/router/experts]
                                              - -low confidence- -> [deferred DistilBERT]
                  [Sensor flow accumulator] -> [Network RF] -> Redis
 CONTROL PLANE:   Gateway - -event- -> [RabbitMQ] - -consume- -> [Spring control] -> [PostgreSQL]
                  Detection - -escalation- -> Spring control -> [ticketed WebSocket]
 OPERATOR PLANE:  [React + Nginx dashboard] -> Gateway / Spring control / WebSocket
                  [Adaptation API] -> Spring control
```

**Implementation limits that shape the topology:**

- The runtime HTTP path has no active soft-voting ensemble call, even though ensemble evaluation code exists.
- The early benign triage exit is implemented but `early_exit_enabled = false`, so current requests proceed to router/specialist stages.
- Deferred deep adjudication can affect later source blocking; it cannot reverse a forwarded backend action or a delivered client response.
- The only full route in gateway configuration targets the demo backend; application records do not dynamically produce gateway routes.
- Control WebSocket tickets are memory-only, reusable for ten minutes and origin patterns are unrestricted in code.
- Container compose uses development-local published ports. This README intentionally contains no live endpoint, credential, service-health, queue-depth, or database-row assertion.

## 37. Verification checklist for this README

- **Source paths checked:** Python contracts/features/runtime/service/data/training; Java gateway/filter/client/behaviour/events/policy; Java control events/security/plane/training/Flyway; sensor flow/Redis; dashboard proxy/API; Compose/Dockerfiles/configuration/tests and saved artifact metadata.
- **Runtime models separated:** saved/evaluated ensembles and char-CNN candidates are labelled inactive; triage/router/injection/execution/network and DistilBERT are labelled deployed/called according to `load_adaptive_pipeline` and `AdaptiveDetectionPipeline`.
- **Exact schemas covered:** all 24 HTTP vector entries and all 38 network vector entries are individually named; network manifest validation and HTTP canonical ordering are described.
- **No operational mutations:** no Compose action, service start/stop, training, model write, database mutation, or queue interaction was performed.

## Documentation evidence and scope

This README was constructed from the source and configuration files in this repository, Flyway migrations, service/container definitions, test and verification scripts, the saved ATRDF/CICIDS manifests, and these saved runtime artifacts:

- `artifacts/benchmarks/phase1-benchmark-v1/metrics.json`
- `artifacts/benchmarks/smoke-phase1-benchmark-v1/metrics.json`
- `artifacts/evaluations/phase10-summary.json`
- selected deployed-model `metrics.json`, calibration metrics, deployment TOML, class mappings, and feature manifests

No training, model rebuilding, Docker image build, Compose lifecycle action, active service call, database mutation, or benchmark was run to create this documentation. Runtime values not present in those saved artifacts—including current service health, live database rows, live queue depth, external-system performance, and production traffic behaviour—are intentionally not claimed.
