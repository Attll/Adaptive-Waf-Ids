from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from adaptive_waf.contracts import NetworkClass
from adaptive_waf.data.cicids import CicidsDatasetLoader, CicidsSchema


class CicidsLoaderTests(unittest.TestCase):
    def test_loader_keeps_network_features_separate_from_http_samples(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "flows.csv"
            source.write_text("flow_duration,packets,label\n12.5,3,DoS-Hulk\n", encoding="utf-8")
            loader = CicidsDatasetLoader(
                CicidsSchema(label_column="label", feature_columns=("flow_duration", "packets")),
                label_aliases={"DoS-Hulk": NetworkClass.DOS_DDOS},
            )

            sample = loader.load_file(source)[0]

            self.assertEqual(sample.label, NetworkClass.DOS_DDOS)
            self.assertEqual(sample.features, {"flow_duration": 12.5, "packets": 3.0})


if __name__ == "__main__":
    unittest.main()
