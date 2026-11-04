FROM python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS dependencies
WORKDIR /app
COPY pyproject.toml ./
RUN python -m venv /opt/venv && python -c "import tomllib; p=tomllib.load(open('pyproject.toml','rb'))['project']; open('/tmp/requirements.txt','w').write('\n'.join(p['dependencies']+p['optional-dependencies']['service']+p['optional-dependencies']['durable']))" && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt 'scikit-learn==1.9.0' 'joblib==1.5.3'

FROM dependencies AS deep-dependencies
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN /opt/venv/bin/pip install --no-cache-dir --index-url ${TORCH_INDEX_URL} 'torch==2.13.0'
RUN /opt/venv/bin/pip install --no-cache-dir 'transformers==5.16.1'

FROM python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS base
ENV PATH=/opt/venv/bin:$PATH PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false
WORKDIR /app
RUN useradd --uid 10001 --create-home waf && mkdir -p /app/artifacts && chown waf:waf /app/artifacts
COPY --from=dependencies /opt/venv /opt/venv
RUN /opt/venv/bin/pip install --no-cache-dir 'psutil>=7,<8'
COPY src ./src
COPY configs ./configs
COPY scripts ./scripts
COPY datasets/samples ./datasets/samples
USER waf
ENTRYPOINT ["python","scripts/release_entrypoint.py"]

FROM base AS sensor
COPY release-build/artifacts/training/network ./artifacts/training/network
COPY release-build/sensor-model-manifest.json ./model-manifest.json
CMD ["python","-m","scripts.run_network_sensor","--host","0.0.0.0"]

FROM base AS adaptation
USER root
RUN mkdir -p /app/artifacts/adaptation && chown -R waf:waf /app/artifacts/adaptation
USER waf
CMD ["python","-m","scripts.run_training_adaptation_service","--host","0.0.0.0"]

FROM base AS detection
COPY --from=deep-dependencies /opt/venv /opt/venv
COPY release-build/artifacts ./artifacts
COPY release-build/model-manifest.json ./model-manifest.json
USER root
RUN chown -R waf:waf /app/artifacts
USER waf
CMD ["python","-m","uvicorn","adaptive_waf.service.app:app","--host","0.0.0.0","--port","8000"]
