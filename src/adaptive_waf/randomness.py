from __future__ import annotations

import os
import random


def seed_everything(seed: int) -> None:
    if seed < 0:
        raise ValueError("seed must not be negative")

    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    _seed_numpy(seed)


def _seed_numpy(seed: int) -> None:
    try:
        import numpy
    except ModuleNotFoundError:
        return
    numpy.random.seed(seed)
