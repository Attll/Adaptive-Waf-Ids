FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY datasets/samples ./datasets/samples
COPY scripts ./scripts
RUN pip install --no-cache-dir ".[service]"
EXPOSE 8084
CMD ["python", "-m", "scripts.run_training_adaptation_service", "--host", "0.0.0.0"]
