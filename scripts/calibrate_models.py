from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

import joblib

from adaptive_waf.config import load_settings
from adaptive_waf.training.calibration import calibrate_sklearn_model, probability_quality
from adaptive_waf.training.deep_calibration import fit_temperature, load_distilbert_logits, probabilities_from_logits
from adaptive_waf.training.deep_data import load_deep_dataset
from adaptive_waf.training.deep_evaluation import evaluate_deep_predictions
from adaptive_waf.training.evaluation import evaluate_classifier
from adaptive_waf.training.expert_data import load_expert_dataset
from adaptive_waf.training.http_data import load_triage_dataset


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    output_directory = settings.paths.artifacts / "training" / "calibration" / arguments.run_id
    output_directory.mkdir(parents=True, exist_ok=False)
    dataset_directory = settings.paths.processed_data / "atrdf" / str(config["dataset_version"])
    results: dict[str, object] = {}
    for name, model_config in config["models"].items():
        calibration, test = _load_classical_splits(dataset_directory, model_config, arguments.max_samples_per_class)
        model = joblib.load(settings.paths.project_root / str(model_config["artifact"]))
        model_results: dict[str, object] = {"uncalibrated": _sklearn_result(model, test, int(config["bins"]))}
        for method in config["methods"]:
            calibrated = calibrate_sklearn_model(model, calibration.features, calibration.labels, method)
            method_directory = output_directory / name / method
            method_directory.mkdir(parents=True)
            joblib.dump(calibrated, method_directory / "model.joblib")
            result = _sklearn_result(calibrated, test, int(config["bins"]))
            (method_directory / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            model_results[str(method)] = result
            print(f"Calibrated {name} with {method}: ece={result['quality']['top_label_expected_calibration_error']:.6f}")
        results[name] = model_results
    results["deep"] = _calibrate_deep(settings, config, dataset_directory, output_directory, arguments.max_samples_per_class)
    (output_directory / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (output_directory / "metrics.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Calibration completed: {output_directory}")


def _load_classical_splits(dataset_directory, model_config, max_samples):
    if model_config["dataset_kind"] == "triage":
        loader = lambda path: load_triage_dataset(path, max_samples)
    else:
        classes = tuple(str(item) for item in model_config["classes"])
        loader = lambda path: load_expert_dataset(path, classes, max_samples)
    return loader(dataset_directory / "validation.jsonl"), loader(dataset_directory / "test.jsonl")


def _sklearn_result(model, dataset, bins: int):
    evaluation = evaluate_classifier(model, dataset.features, dataset.labels)
    return {"evaluation": evaluation.as_dict(), "quality": probability_quality(model.predict_proba(dataset.features), dataset.labels, [str(label) for label in model.classes_], bins)}


def _calibrate_deep(settings, config, dataset_directory, output_directory, max_samples):
    deep = config["deep"]
    classes = tuple(str(item) for item in deep["classes"])
    validation = load_deep_dataset(dataset_directory / "validation.jsonl", classes, max_samples)
    test = load_deep_dataset(dataset_directory / "test.jsonl", classes, max_samples)
    artifact_directory = settings.paths.project_root / str(deep["artifact"])
    options = _load_json(artifact_directory / "config.json")["config"]["candidates"][deep["candidate"]]
    calibration_logits, _ = load_distilbert_logits(artifact_directory, validation.texts, int(options["batch_size"]), int(options["max_length"]), str(config["device"]))
    temperature = fit_temperature(calibration_logits, validation.labels, classes, str(config["device"]))
    test_logits, durations = load_distilbert_logits(artifact_directory, test.texts, int(options["batch_size"]), int(options["max_length"]), str(config["device"]))
    uncalibrated = probabilities_from_logits(test_logits, 1.0)
    calibrated = probabilities_from_logits(test_logits, temperature)
    result = {
        "temperature": temperature,
        "uncalibrated": {"evaluation": evaluate_deep_predictions(test.labels, uncalibrated, classes, durations).as_dict(), "quality": probability_quality(uncalibrated, test.labels, classes, int(config["bins"]))},
        "calibrated": {"evaluation": evaluate_deep_predictions(test.labels, calibrated, classes, durations).as_dict(), "quality": probability_quality(calibrated, test.labels, classes, int(config["bins"]))},
    }
    directory = output_directory / "deep"
    directory.mkdir(parents=True)
    (directory / "temperature.json").write_text(json.dumps({"temperature": temperature}, indent=2) + "\n", encoding="utf-8")
    (directory / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Calibrated deep model: temperature={temperature:.6f}")
    return result


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate selected HTTP model probabilities against validation data.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/calibration.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    return parser.parse_args()


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
