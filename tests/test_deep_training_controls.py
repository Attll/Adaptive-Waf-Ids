import json
from pathlib import Path
import tempfile
import unittest
import importlib.util
from adaptive_waf.training.deep_training import train_char_cnn, _resolve_device
from adaptive_waf.training.deep_data import DeepTextDataset


@unittest.skipUnless(importlib.util.find_spec("torch"), "optional torch dependency required")
class DeepTrainingControlTests(unittest.TestCase):
    def test_tiny_cpu_training_persists_checkpoint_and_manifest(self):
        import torch
        prior = torch.get_num_threads()
        torch.set_num_threads(1)
        try:
            data = DeepTextDataset(["ordinary text", "suspicious text"], ["BENIGN","XSS"])
            options = {"epochs": 1, "batch_size": 2, "max_length": 16, "embedding_dimension": 4,
                       "filters": 2, "dropout": 0., "learning_rate": .001}
            with tempfile.TemporaryDirectory() as directory:
                train_char_cnn(data, data, ("BENIGN","XSS"), options, Path(directory), 641, "cpu")
                manifest = json.loads((Path(directory) / "training_manifest.json").read_text())
                self.assertEqual(manifest["device"], "cpu")
                self.assertFalse(manifest["final_test_used"])
                self.assertTrue((Path(directory) / "best_checkpoint.pt").is_file())
        finally:
            torch.set_num_threads(prior)
