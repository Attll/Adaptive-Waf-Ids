from __future__ import annotations

from time import perf_counter_ns
from typing import Sequence

from adaptive_waf.training.deep_training import _require_torch, _require_transformers, _resolve_device


def load_distilbert_logits(artifact_directory, texts: Sequence[str], batch_size: int, max_length: int, device_name: str):
    torch = _require_torch()
    AutoModelForSequenceClassification, AutoTokenizer = _require_transformers()
    device = _resolve_device(torch, device_name)
    model = AutoModelForSequenceClassification.from_pretrained(artifact_directory / "model").to(device).eval()
    tokenizer = AutoTokenizer.from_pretrained(artifact_directory / "tokenizer")
    logits: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        inputs = tokenizer(texts[start : start + batch_size], truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        with torch.no_grad():
            logits.extend(model(**{name: values.to(device) for name, values in inputs.items()}).logits.cpu().tolist())
    durations: list[float] = []
    for text in texts[: min(len(texts), 128)]:
        start = perf_counter_ns()
        inputs = tokenizer([text], truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        with torch.no_grad():
            model(**{name: values.to(device) for name, values in inputs.items()})
        durations.append((perf_counter_ns() - start) / 1_000_000)
    return logits, durations


def fit_temperature(logits: Sequence[Sequence[float]], labels: Sequence[str], class_order: Sequence[str], device_name: str) -> float:
    torch = _require_torch()
    device = _resolve_device(torch, device_name)
    targets = torch.tensor([class_order.index(label) for label in labels], dtype=torch.long, device=device)
    values = torch.tensor(logits, dtype=torch.float32, device=device)
    log_temperature = torch.zeros(1, requires_grad=True, device=device)
    optimizer = torch.optim.LBFGS([log_temperature], lr=0.1, max_iter=50)

    def closure():
        optimizer.zero_grad()
        loss = torch.nn.functional.cross_entropy(values / log_temperature.exp(), targets)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(log_temperature.exp().detach().cpu().item())


def probabilities_from_logits(logits: Sequence[Sequence[float]], temperature: float) -> list[list[float]]:
    torch = _require_torch()
    return torch.softmax(torch.tensor(logits, dtype=torch.float32) / temperature, dim=1).tolist()
