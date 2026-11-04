# Adaptive WAF-IDS release deployment

This release configuration is separate from the preserved legacy local Compose deployment. It runs seven application images plus PostgreSQL, Redis, RabbitMQ and OWASP CRS. Deferred workers run inside detection and use RabbitMQ and PostgreSQL; control migrations must complete before detection starts. CPU inference is the default. Microbatching is disabled. Conformal, bandit and live adaptation are not enabled.

Copy `.env.example` to `.env` in this directory and replace every credential placeholder. Use random hex values for database/broker credentials because they enter connection URLs. Do not commit or export `.env`. For a new machine build with the provided scripts; a portable exported bundle uses imported images with no rebuild. The release bundle never contains credentials.

```powershell
.\scripts\release.ps1 Build
.\scripts\release.ps1 Validate
.\scripts\release.ps1 Start
.\scripts\release.ps1 Health
.\scripts\release.ps1 Smoke
.\scripts\release.ps1 Logs
.\scripts\release.ps1 Stop
.\scripts\release.ps1 Export
.\scripts\release.ps1 Import
```

Dashboard: `http://127.0.0.1:3000`; use ADMIN_USERNAME/ADMIN_PASSWORD from your private environment. Gateway: `http://127.0.0.1:8080/backend/`. Detection readiness: `http://127.0.0.1:8000/ready`. Control: 8082; sensor: 8083; adaptation: 8084; CRS: 8090. Override each published port with SERVICE_PORT (dashboard 3000); all bindings are loopback. Demo 8081, PostgreSQL 5432, Redis 6379 and RabbitMQ 5672 are internal only; broker management is not published. Docker network DNS uses service names.

PostgreSQL, RabbitMQ and Redis have named volumes. Ordinary shutdown uses `down` **without `-v`**. Credentials for existing databases/broker volumes are not rotated merely by editing environment variables. Back up volumes and use service-specific rotation procedures. All release actions affect only the specified Compose project; never prune unrelated Docker resources.

The baseline manifest is verified before staging and by detection's entrypoint. Baseline artifacts remain unchanged, candidates stay outside release images. Replace a model only through a reviewed, versioned image and its matching manifest/configuration; retain the previous image tag/ID and data backup for rollback. Registry status in the dashboard is administrative metadata, not automatic runtime model loading. Internal service routes require the shared token and are blocked by the browser proxy. Browser-facing helper APIs retain local-demo semantics; this is not a publicly exposed production deployment/security certification.

The optional GPU override needs a compatible Docker Desktop/WSL2 NVIDIA setup and a separate CUDA image build. Use both `-f .../compose.yml -f .../compose.gpu.yml` with `--env-file .../.env`, build detection, then start. CUDA wheels are larger; ordinary CPU images cannot become CUDA-enabled just by adding `gpus: all`. Device selection `auto` falls back to CPU when PyTorch cannot use CUDA. GPU-container acceleration is unverified until its separate image is built and exercised. Host CUDA inference evidence is not container GPU evidence.

Troubleshooting: run `Logs` and inspect `/ready` before traffic. A missing artifact/hash mismatch aborts detection before serving. If the broker/database is not healthy, detection intentionally waits for control migrations. A changed port does not alter internal service DNS. If image pulls fail, restore connectivity or import a verified bundle; image creation alone does not demonstrate readiness. Failed health/dependency tests remain failures until fixed.

The requested cumulative training cap is 60 minutes; release packaging does not start training. The old 90-minute experiment is obsolete. Given the tiny independent attack populations, further training is deferred in favor of delivery. No new candidate accuracy or trained adaptive-policy benefit is claimed.
