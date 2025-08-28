import numpy as np
from typing import Tuple, Dict

class LaplaceMechanism:
    def __init__(self, epsilon: float = 1.0, sensitivity: float = 1.0):
        if epsilon <= 0:
            raise ValueError("epsilon must be > 0")
        self.epsilon = epsilon
        self.sensitivity = sensitivity

    def add_noise(self, value: float) -> Tuple[float, Dict]:
        scale = self.sensitivity / self.epsilon
        noise = np.random.laplace(0.0, scale)
        noised = float(value + noise)
        report = {
            "original": value,
            "noised": noised,
            "epsilon": self.epsilon,
            "sensitivity": self.sensitivity,
            "noise": float(noise),
            "mechanism": "Laplace",
        }
        return noised, report
