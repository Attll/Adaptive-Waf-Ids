from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from adaptive_waf.config import load_settings


class ConfigTests(unittest.TestCase):
    def test_load_settings_resolves_paths_from_project_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config_directory = root / "configs"
            config_directory.mkdir()
            config_path = config_directory / "core.toml"
            config_path.write_text(
                '\n'.join(
                    [
                        'schema_version = "1"',
                        "random_seed = 12",
                        'feature_version = "http-v1"',
                        "[paths]",
                        'raw_data = "datasets/raw"',
                        'processed_data = "datasets/processed"',
                        'artifacts = "artifacts"',
                    ]
                ),
                encoding="utf-8",
            )

            settings = load_settings(config_path)

            self.assertEqual(settings.paths.project_root, root.resolve())
            self.assertEqual(settings.paths.artifacts, (root / "artifacts").resolve())
            settings.paths.create_generated_directories()
            self.assertTrue(settings.paths.artifacts.is_dir())


if __name__ == "__main__":
    unittest.main()
