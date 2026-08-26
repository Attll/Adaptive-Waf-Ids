from __future__ import annotations

import argparse
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.contracts import NetworkClass
from adaptive_waf.data.cicids import CicidsDatasetLoader, CicidsSchema
from adaptive_waf.data.preparation import SplitRatios, prepare_network_samples


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    sources = [settings.paths.project_root / path for path in config["sources"]]
    output_directory = arguments.output_dir or settings.paths.processed_data / "cicids2018" / config["dataset_version"]
    loader = CicidsDatasetLoader(
        schema=CicidsSchema(
            label_column="Label",
            feature_columns=tuple(config["features"]),
            non_finite_replacement=float(config["non_finite_replacement"]),
        ),
        label_aliases={label: NetworkClass(network_class) for label, network_class in config["labels"].items()},
    )
    summary = prepare_network_samples(
        samples=(sample for source in sources for sample in loader.iter_file(source)),
        output_directory=output_directory,
        ratios=SplitRatios(**config["split"]),
        seed=settings.random_seed,
        source_paths=sources,
    )
    print(f"Prepared CICIDS data: {summary.output_directory}")
    print(f"Split counts: {dict(summary.split_counts)}")
    print(f"Class counts: {dict(summary.class_counts)}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare leakage-safe CICIDS JSONL splits.")
    parser.add_argument("--config", type=Path, default=Path("configs/data/cicids2018.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args()


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


if __name__ == "__main__":
    main()
