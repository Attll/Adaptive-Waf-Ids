from __future__ import annotations

import json
from pathlib import Path
import tomllib

import joblib

from adaptive_waf.config import load_settings
from adaptive_waf.contracts import AttackClass, ExpertFamily, HttpRequestRecord
from adaptive_waf.features.canonical import serialize_deep_request
from adaptive_waf.runtime.pipeline import AdaptiveDetectionPipeline, PipelineThresholds


def load_adaptive_pipeline(core_config: Path | None = None) -> AdaptiveDetectionPipeline:
    settings = load_settings(core_config)
    root = settings.paths.project_root
    triage = _toml(root / "configs/models/triage_deployment.toml")
    router = _toml(root / "configs/models/router_deployment.toml")
    injection = _toml(root / "configs/models/injection_expert_deployment.toml")
    execution = _toml(root / "configs/models/execution_expert_deployment.toml")
    calibration = _toml(root / "configs/models/calibration_deployment.toml")
    pipeline_config = _toml(root / "configs/models/pipeline.toml")
    deep = _toml(root / "configs/models/deep_deployment.toml")
    return AdaptiveDetectionPipeline(
        joblib.load(root / calibration["triage"]["artifact"]),
        joblib.load(root / router["artifact"]),
        {
            ExpertFamily.INJECTION: joblib.load(root / calibration["injection"]["artifact"]),
            ExpertFamily.EXECUTION: joblib.load(root / calibration["execution"]["artifact"]),
        },
        PipelineThresholds(
            float(pipeline_config["triage_benign_exit_max_suspicious_probability"]),
            bool(pipeline_config["triage_early_exit_enabled"]),
            float(pipeline_config["expert_minimum_confidence"]),
            float(router["minimum_top1_probability"]),
            float(router["minimum_top1_margin"]),
        ),
        {
            "triage": f"{triage['run_id']}:{calibration['triage']['method']}",
            "router": f"{router['run_id']}:{router['algorithm']}",
            "injection": f"{injection['run_id']}:{calibration['injection']['method']}",
            "execution": f"{execution['run_id']}:{calibration['execution']['method']}",
            "deep": f"{deep['run_id']}:{calibration['deep']['method']}",
        },
        DistilBertPredictor(root / deep["artifact"], root / calibration["deep"]["artifact"], str(deep["device"])),
    )


class DistilBertPredictor:
    def __init__(self, artifact_directory: Path, temperature_path: Path, device_name: str) -> None:
        self._artifact_directory = artifact_directory
        self._temperature = float(json.loads(temperature_path.read_text(encoding="utf-8"))["temperature"])
        self._device_name = device_name
        self._model = None
        self._tokenizer = None

    def __call__(self, request: HttpRequestRecord) -> dict[AttackClass, float]:
        torch, model, tokenizer, device = self._loaded()
        inputs = tokenizer(serialize_deep_request(request), truncation=True, max_length=256, return_tensors="pt")
        with torch.no_grad():
            probabilities = torch.softmax(model(**{name: value.to(device) for name, value in inputs.items()}).logits / self._temperature, dim=1)[0].cpu().tolist()
        return {AttackClass(model.config.id2label[index]): float(value) for index, value in enumerate(probabilities)}

    def _loaded(self):
        if self._model is None:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            device = torch.device(self._device_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(self._artifact_directory / "model").to(device).eval()
            self._tokenizer = AutoTokenizer.from_pretrained(self._artifact_directory / "tokenizer")
        import torch

        return torch, self._model, self._tokenizer, torch.device(self._device_name)


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)
