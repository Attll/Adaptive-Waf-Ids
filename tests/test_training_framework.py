from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from adaptive_waf.training.models import CandidateAlgorithm
from adaptive_waf.training.runner import train_candidates


class TrainingFrameworkTests(unittest.TestCase):
    def test_candidate_training_persists_metrics_and_model(self) -> None:
        train_features = [[0.0, 0.0], [0.1, 0.1], [1.0, 1.0], [0.9, 0.9]]
        train_labels = ["BENIGN", "BENIGN", "SUSPICIOUS", "SUSPICIOUS"]
        validation_features = [[0.05, 0.05], [0.95, 0.95]]
        validation_labels = ["BENIGN", "SUSPICIOUS"]

        with TemporaryDirectory() as directory:
            runs = train_candidates(
                train_features,
                train_labels,
                validation_features,
                validation_labels,
                feature_names=("first", "second"),
                output_directory=Path(directory) / "run",
                random_seed=641,
                algorithms=(CandidateAlgorithm.LOGISTIC_REGRESSION,),
            )

            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0].artifact_directory / "model.joblib").is_file())
            self.assertTrue((runs[0].artifact_directory / "metrics.json").is_file())
            self.assertEqual(runs[0].evaluation.accuracy, 1.0)


if __name__ == "__main__":
    unittest.main()
