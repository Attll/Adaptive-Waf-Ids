from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter_ns
import copy
import contextlib
import platform
from typing import Callable, Mapping, Sequence

from adaptive_waf.training.deep_data import CharacterTokenizer, DeepTextDataset
from adaptive_waf.training.deep_evaluation import DeepEvaluationResult, evaluate_deep_predictions


def ensure_deep_dependencies(candidate: str) -> None:
    _require_torch()
    if candidate == "distilbert":
        _require_transformers()


def train_char_cnn(
    train: DeepTextDataset,
    validation: DeepTextDataset,
    classes: tuple[str, ...],
    options: Mapping[str, object],
    output_directory: Path,
    seed: int,
    device_name: str,
) -> DeepEvaluationResult:
    torch = _require_torch()
    _seed(torch, seed)
    tokenizer = CharacterTokenizer()
    device = _resolve_device(torch, device_name)
    model = _build_char_cnn(torch, tokenizer.vocabulary_size, len(classes), options).to(device)
    class_ids = {label: index for index, label in enumerate(classes)}
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(options["learning_rate"]))
    loss_function = torch.nn.CrossEntropyLoss()
    scaler = torch.amp.GradScaler("cuda", enabled=device.type == "cuda")
    best_loss, stale, history = float("inf"), 0, []
    for epoch in range(1, int(options["epochs"]) + 1):
        model.train()
        for indexes in _batch_indexes(torch, len(train.texts), int(options["batch_size"]), seed + epoch):
            inputs = _transfer(torch.tensor([tokenizer.encode(train.texts[index], int(options["max_length"])) for index in indexes], dtype=torch.long), device)
            targets = _transfer(torch.tensor([class_ids[train.labels[index]] for index in indexes], dtype=torch.long), device)
            optimizer.zero_grad()
            with torch.autocast(device_type=device.type, enabled=device.type == "cuda"):
                loss = loss_function(model(inputs), targets)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), float(options.get("gradient_clip", 1)))
            scaler.step(optimizer)
            scaler.update()
        model.eval()
        probabilities, _ = _char_probabilities(torch, model, tokenizer, validation.texts, int(options["max_length"]), int(options["batch_size"]), device, profile=False)
        validation_loss = _validation_loss(probabilities, validation.labels, class_ids)
        history.append({"epoch": epoch, "validation_loss": validation_loss})
        if validation_loss < best_loss:
            best_loss, stale = validation_loss, 0
            torch.save({"state_dict": model.state_dict(), "optimizer": optimizer.state_dict(), "epoch": epoch}, output_directory / "best_checkpoint.pt")
        else:
            stale += 1
        print(f"char_cnn epoch {epoch}/{options['epochs']} completed")
        if stale >= int(options.get("patience", 2)):
            break
    model.load_state_dict(torch.load(output_directory / "best_checkpoint.pt", map_location=device, weights_only=True)["state_dict"])
    _manifest(torch, device, seed, history, output_directory)
    probabilities, durations = _char_probabilities(torch, model, tokenizer, validation.texts, int(options["max_length"]), int(options["batch_size"]), device)
    evaluation = evaluate_deep_predictions(validation.labels, probabilities, classes, durations)
    torch.save({"state_dict": model.state_dict(), "classes": classes, "options": dict(options)}, output_directory / "model.pt")
    (output_directory / "vocabulary.json").write_text(json.dumps(tokenizer.as_dict(), indent=2) + "\n", encoding="utf-8")
    return evaluation


def train_distilbert(
    train: DeepTextDataset,
    validation: DeepTextDataset,
    classes: tuple[str, ...],
    options: Mapping[str, object],
    output_directory: Path,
    seed: int,
    device_name: str,
) -> DeepEvaluationResult:
    torch = _require_torch()
    _seed(torch, seed)
    AutoModelForSequenceClassification, AutoTokenizer = _require_transformers()
    device = _resolve_device(torch, device_name)
    class_ids = {label: index for index, label in enumerate(classes)}
    tokenizer = AutoTokenizer.from_pretrained(str(options.get("tokenizer_source", options["pretrained_model"])))
    model = AutoModelForSequenceClassification.from_pretrained(
        str(options["pretrained_model"]),
        num_labels=len(classes),
        id2label={index: label for index, label in enumerate(classes)},
        label2id=class_ids,
    ).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(options["learning_rate"]))
    scaler = torch.amp.GradScaler("cuda", enabled=device.type == "cuda")
    best_loss, stale, history = float("inf"), 0, []
    for epoch in range(1, int(options["epochs"]) + 1):
        model.train()
        for indexes in _batch_indexes(torch, len(train.texts), int(options["batch_size"]), seed + epoch):
            batch = tokenizer([train.texts[index] for index in indexes], truncation=True, padding=True, max_length=int(options["max_length"]), return_tensors="pt")
            targets = torch.tensor([class_ids[train.labels[index]] for index in indexes], dtype=torch.long)
            batch = {name: _transfer(values, device) for name, values in batch.items()}
            optimizer.zero_grad()
            with torch.autocast(device_type=device.type, enabled=device.type == "cuda"):
                loss = model(**batch, labels=_transfer(targets, device)).loss
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), float(options.get("gradient_clip", 1)))
            scaler.step(optimizer)
            scaler.update()
        model.eval()
        probabilities, _ = _transformer_probabilities(torch, model, tokenizer, validation.texts, int(options["max_length"]), int(options["batch_size"]), device, profile=False)
        validation_loss = _validation_loss(probabilities, validation.labels, class_ids)
        history.append({"epoch": epoch, "validation_loss": validation_loss})
        if validation_loss < best_loss:
            best_loss, stale = validation_loss, 0
            torch.save({"state_dict": model.state_dict(), "optimizer": optimizer.state_dict(), "epoch": epoch}, output_directory / "best_checkpoint.pt")
        else:
            stale += 1
        print(f"distilbert epoch {epoch}/{options['epochs']} completed")
        if stale >= int(options.get("patience", 2)):
            break
    model.load_state_dict(torch.load(output_directory / "best_checkpoint.pt", map_location=device, weights_only=True)["state_dict"])
    _manifest(torch, device, seed, history, output_directory)
    probabilities, durations = _transformer_probabilities(torch, model, tokenizer, validation.texts, int(options["max_length"]), int(options["batch_size"]), device)
    evaluation = evaluate_deep_predictions(validation.labels, probabilities, classes, durations)
    model.save_pretrained(output_directory / "model")
    tokenizer.save_pretrained(output_directory / "tokenizer")
    return evaluation


def _build_char_cnn(torch, vocabulary_size: int, class_count: int, options: Mapping[str, object]):
    class CharacterCnn(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            embedding_dimension = int(options["embedding_dimension"])
            filters = int(options["filters"])
            self.embedding = torch.nn.Embedding(vocabulary_size, embedding_dimension, padding_idx=0)
            self.convolutions = torch.nn.ModuleList([torch.nn.Conv1d(embedding_dimension, filters, width) for width in (3, 5, 7)])
            self.dropout = torch.nn.Dropout(float(options["dropout"]))
            self.classifier = torch.nn.Linear(filters * 3, class_count)

        def forward(self, inputs):
            embedded = self.embedding(inputs).transpose(1, 2)
            pooled = [torch.nn.functional.relu(convolution(embedded)).amax(dim=2) for convolution in self.convolutions]
            return self.classifier(self.dropout(torch.cat(pooled, dim=1)))

    return CharacterCnn()


def _char_probabilities(torch, model, tokenizer, texts, max_length: int, batch_size: int, device, profile=True):
    def infer(batch_texts):
        inputs = torch.tensor([tokenizer.encode(text, max_length) for text in batch_texts], dtype=torch.long, device=device)
        with torch.no_grad():
            return torch.softmax(model(inputs), dim=1).cpu().tolist()

    return _probabilities_and_durations(infer, texts, batch_size, profile)


def _transformer_probabilities(torch, model, tokenizer, texts, max_length: int, batch_size: int, device, profile=True):
    def infer(batch_texts):
        inputs = tokenizer(batch_texts, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        with torch.no_grad():
            return torch.softmax(model(**{name: values.to(device) for name, values in inputs.items()}).logits, dim=1).cpu().tolist()

    return _probabilities_and_durations(infer, texts, batch_size, profile)


def _probabilities_and_durations(infer: Callable[[Sequence[str]], list[list[float]]], texts: Sequence[str], batch_size: int, profile=True) -> tuple[list[list[float]], list[float]]:
    probabilities: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        probabilities.extend(infer(texts[start : start + batch_size]))
    durations: list[float] = []
    for text in texts[: min(128, len(texts))] if profile else ():
        start = perf_counter_ns()
        infer([text])
        durations.append((perf_counter_ns() - start) / 1_000_000)
    return probabilities, durations


def _batch_indexes(torch, count: int, batch_size: int, seed: int):
    generator = torch.Generator().manual_seed(seed)
    order = torch.randperm(count, generator=generator).tolist()
    for start in range(0, count, batch_size):
        yield order[start : start + batch_size]


def _resolve_device(torch, configured: str):
    if configured == "auto" or (configured.startswith("cuda") and not torch.cuda.is_available()):
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(configured)


def _seed(torch, seed):
    from adaptive_waf.randomness import seed_everything
    seed_everything(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.benchmark = False
    torch.use_deterministic_algorithms(True, warn_only=True)


def _transfer(values, device):
    if device.type == "cuda":
        return values.pin_memory().to(device, non_blocking=True)
    return values.to(device)


def _validation_loss(rows, labels, indexes):
    import math
    if not rows or len(rows) != len(labels):
        raise ValueError("nonempty validation data required")
    return -sum(math.log(max(1e-12, row[indexes[label]])) for row, label in zip(rows, labels, strict=True)) / len(labels)


def _manifest(torch, device, seed, history, directory):
    value = {"seed": seed, "device": str(device), "torch_version": torch.__version__, "python": platform.python_version(),
             "cuda_runtime": torch.version.cuda, "mixed_precision": device.type == "cuda", "history": history,
             "peak_allocated_bytes": torch.cuda.max_memory_allocated(device) if device.type == "cuda" else 0,
             "selection_population": "validation_only", "final_test_used": False}
    (directory / "training_manifest.json").write_text(json.dumps(value, indent=2) + "\n")


def _require_torch():
    try:
        import torch
    except ModuleNotFoundError as error:
        raise RuntimeError("deep training requires the optional dependencies: pip install -e '.[deep]'") from error
    return torch


def _require_transformers():
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ModuleNotFoundError as error:
        raise RuntimeError("DistilBERT training requires transformers: pip install -e '.[deep]'") from error
    return AutoModelForSequenceClassification, AutoTokenizer
