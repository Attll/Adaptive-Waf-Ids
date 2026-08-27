FROM python:3.11-slim
WORKDIR /app

# The container has no GPU, so the deep model runs on CPU (deep_deployment.toml's cuda setting falls back
# automatically). Installing torch from the CPU wheel index first keeps the multi-gigabyte CUDA runtime out of the
# image: the default index pulls nvidia-*, triton, and cuda-toolkit wheels that can never be used here.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --index-url ${TORCH_INDEX_URL} "torch>=2.7,<3"

COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY datasets/samples ./datasets/samples
COPY artifacts/training ./artifacts/training
RUN pip install --no-cache-dir ".[service,deep]"
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "adaptive_waf.service.app:app", "--host", "0.0.0.0", "--port", "8000"]
