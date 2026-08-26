from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter_ns
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
    tokenizer = CharacterTokenizer()
    device = _resolve_device(torch, device_name)
    model = _build_char_cnn(torch, tokenizer.vocabulary_size, len(classes), options).to(device)
    class_ids = {label: index for index, label in enumerate(classes)}
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(options["learning_rate"]))
    loss_function = torch.nn.CrossEntropyLoss()
    for epoch in range(1, int(options["epochs"]) + 1):
        model.train()
        for indexes in _batch_indexes(torch, len(train.texts), int(options["batch_size"]), seed + epoch):
            inputs = torch.tensor([tokenizer.encode(train.texts[index], int(options["max_length"])) for index in indexes], dtype=torch.long, device=device)
            targets = torch.tensor([class_ids[train.labels[index]] for index in indexes], dtype=torch.long, device=device)
            optimizer.zero_grad()
            loss_function(model(inputs), targets).backward()
            optimizer.step()
        print(f"char_cnn epoch {epoch}/{options['epochs']} completed")
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
    AutoModelForSequenceClassification, AutoTokenizer = _require_transformers()
    device = _resolve_device(torch, device_name)
    class_ids = {label: index for index, label in enumerate(classes)}
    tokenizer = AutoTokenizer.from_pretrained(str(options["pretrained_model"]))
    model = AutoModelForSequenceClassification.from_pretrained(
        str(options["pretrained_model"]),
        num_labels=len(classes),
        id2label={index: label for index, label in enumerate(classes)},
        label2id=class_ids,
    ).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(options["learning_rate"]))
    for epoch in range(1, int(options["epochs"]) + 1):
        model.train()
        for indexes in _batch_indexes(torch, len(train.texts), int(options["batch_size"]), seed + epoch):
            batch = tokenizer([train.texts[index] for index in indexes], truncation=True, padding=True, max_length=int(options["max_length"]), return_tensors="pt")
            targets = torch.tensor([class_ids[train.labels[index]] for index in indexes], dtype=torch.long)
            batch = {name: values.to(device) for name, values in batch.items()}
            optimizer.zero_grad()
            model(**batch, labels=targets.to(device)).loss.backward()
            optimizer.step()
        print(f"distilbert epoch {epoch}/{options['epochs']} completed")
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


def _char_probabilities(torch, model, tokenizer, texts, max_length: int, batch_size: int, device):
    def infer(batch_texts):
        inputs = torch.tensor([tokenizer.encode(text, max_length) for text in batch_texts], dtype=torch.long, device=device)
        with torch.no_grad():
            return torch.softmax(model(inputs), dim=1).cpu().tolist()

    return _probabilities_and_durations(infer, texts, batch_size)


def _transformer_probabilities(torch, model, tokenizer, texts, max_length: int, batch_size: int, device):
    def infer(batch_texts):
        inputs = tokenizer(batch_texts, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        with torch.no_grad():
            return torch.softmax(model(**{name: values.to(device) for name, values in inputs.items()}).logits, dim=1).cpu().tolist()

    return _probabilities_and_durations(infer, texts, batch_size)


def _probabilities_and_durations(infer: Callable[[Sequence[str]], list[list[float]]], texts: Sequence[str], batch_size: int) -> tuple[list[list[float]], list[float]]:
    probabilities: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        probabilities.extend(infer(texts[start : start + batch_size]))
    durations: list[float] = []
    for text in texts[: min(128, len(texts))]:
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
    if configured == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(configured)


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
