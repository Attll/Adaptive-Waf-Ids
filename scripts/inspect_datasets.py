from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptive_waf.config import load_settings
from adaptive_waf.data.inspection import (
    inspect_atrdf_json_file,
    inspect_atrdf_json_tree,
    inspect_csv_file,
    inspect_csv_tree,
)


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.config)
    if arguments.files:
        inspections = (
            [inspect_atrdf_json_file(path) for path in arguments.files]
            if arguments.dataset == "atrdf"
            else [inspect_csv_file(path, arguments.label_column) for path in arguments.files]
        )
    else:
        directory = settings.paths.raw_data / arguments.dataset
        inspections = (
            inspect_atrdf_json_tree(directory)
            if arguments.dataset == "atrdf"
            else inspect_csv_tree(directory, arguments.label_column)
        )
    print(json.dumps([inspection.as_dict() for inspection in inspections], indent=2))


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect CSV dataset schemas and quality signals.")
    parser.add_argument("dataset", choices=("atrdf", "cicids2018"))
    parser.add_argument("--label-column")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--file", dest="files", action="append", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    main()
