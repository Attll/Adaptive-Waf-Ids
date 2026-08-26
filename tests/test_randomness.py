import random
import unittest

from adaptive_waf.randomness import seed_everything


class RandomnessTests(unittest.TestCase):
    def test_seed_everything_repeats_standard_random_sequence(self) -> None:
        seed_everything(641)
        first = [random.random() for _ in range(3)]
        seed_everything(641)
        second = [random.random() for _ in range(3)]

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
