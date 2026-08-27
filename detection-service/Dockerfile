FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY artifacts/training ./artifacts/training
RUN pip install --no-cache-dir ".[service,deep]"
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "adaptive_waf.service.app:app", "--host", "0.0.0.0", "--port", "8000"]
