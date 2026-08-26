from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(frozen=True, slots=True)
class ProjectPaths:
    project_root: Path
    raw_data: Path
    processed_data: Path
    artifacts: Path

    def create_generated_directories(self) -> None:
        self.processed_data.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class CoreSettings:
    schema_version: str
    random_seed: int
    feature_version: str
    paths: ProjectPaths


def load_settings(config_path: Path | str | None = None) -> CoreSettings:
    resolved_path = Path(config_path) if config_path else _default_config_path()
    with resolved_path.open("rb") as config_file:
        config = tomllib.load(config_file)

    root = resolved_path.parent.parent.resolve()
    path_config = config["paths"]
    return CoreSettings(
        schema_version=str(config["schema_version"]),
        random_seed=int(config["random_seed"]),
        feature_version=str(config["feature_version"]),
        paths=ProjectPaths(
            project_root=root,
            raw_data=(root / path_config["raw_data"]).resolve(),
            processed_data=(root / path_config["processed_data"]).resolve(),
            artifacts=(root / path_config["artifacts"]).resolve(),
        ),
    )


def _default_config_path() -> Path:
    return Path(__file__).resolve().parents[2] / "configs" / "core.toml"
