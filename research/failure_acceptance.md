# Reliability evidence and remaining acceptance

Latest complete suite: `runs/final-routing-context-v10/` (114 Python, Java 33 gateway / 10 control / 2 backend, zero failures, dependency integration enabled) plus the final full `runs/final-evidence-v12/` acceptance and `runs/dashboard-final-v11.txt` after display-only browser findings.

| Failure / boundary | Executed evidence | Limit |
|---|---|---|
| Delayed upstream POST / upstream 503 | Actual Spring Cloud Gateway/backend sockets; byte-preserving chunked POST, one backend invocation, unchanged 503 response | Local fixture only |
| Oversized/unsupported/nonterminating body | Gateway unit/HTTP byte and read bounds, multipart rejection before backend | No universal multipart/parser support |
| Detection unavailable / slow native inference | Actual detection HTTP 503, deadline/queue/capacity tests, explicit inspection status | Running native calls cannot be forcefully cancelled |
| Redis windows / rate policy / expiry | Actual isolated Redis concurrent updates, TTL, policy consumption and unknown-verdict rejection | Deployment NAT/proxy/fault matrix incomplete |
| Event publication / duplication / poison | Actual RabbitMQ confirmations/unroutable path, overflow tests, PostgreSQL duplicate and bounded recovery queue | No durable disk spool for gateway event publication |
| Deep producer/worker restart | Actual independent producer restart and abrupt child-process exit while broker delivery unacknowledged and DB lease held | Native execution may run again after lease recovery; not exactly-once side effects |
| Deep saturation/expiry/retry | Real queue/database bounds, TTL/lease expiry, bounded attempts, terminal states and rejected failed-job resubmission | Full partitions/long-duration campaign not executed |
| Result-reporting outage | Real retained terminal DB outbox with reporter failure/retry and acknowledgement | Remote permanent outage retains unresolved reporting; operational handling needed |
| GPU unavailable / allocation failure | CPU fallback selector and injected CUDA OOM CPU retry without filling real VRAM; actual CPU/CUDA read-only profiles | Real sustained memory-pressure acceptance not performed |
| Corrupt artifact / missing required deep | Readiness/load failure tests and conservative explicit unavailable/block recommendation | Safe deserialization assumes trusted local model artifacts |
| Invalid or failed policy activation | Schema/metric gates, shadow default, missing auth, duplicate version, failed runtime ACK restoring baseline, monitored rollback tests | Real live promotion not authorized or run |
| Delayed or incorrect evidence | Immutable original, dedup, reviewed correction, shared-IP session separation, decay/expiry and API integration | Process-local context; no representative containment study |
| Dashboard stream / disconnect | Browser live event receipt, actual filter/visualizer/review/health flows; stopped-dependency fixture demonstrated sign-in failure | Exhaustive reconnection/role matrix not certified |

Unimplemented certification tests are not counted as passes. Assertions injected in unit fixtures are labeled separately from actual broker/database/socket evidence. Production TLS/service identity/exposure and a full long-run fault campaign remain open.

Final complete acceptance: `runs/final-dashboard-v15/` — 117 Python tests, Java gateway/control/backend 33/10/2, zero failures and dashboard build pass. The later policy concurrency/audit failures are exercised with injected local fixtures; no live promotion occurred. Full earlier passing/failed checkpoints remain available.
