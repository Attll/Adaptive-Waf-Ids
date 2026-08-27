FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY scripts ./scripts
COPY artifacts/training/network ./artifacts/training/network
RUN pip install --no-cache-dir ".[service]"
EXPOSE 8083
CMD ["python", "-m", "scripts.run_network_sensor", "--host", "0.0.0.0"]
