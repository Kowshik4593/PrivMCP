from dataclasses import dataclass

@dataclass
class RouteDecision:
    model: str
    reason: str

def decide_model(retrieval_scores: list[float], base: str, strong: str, tau: float = 0.45) -> RouteDecision:
    max_s = max(retrieval_scores) if retrieval_scores else 0.0
    if max_s < tau:
        return RouteDecision(strong, f"escalate: low retrieval score {max_s:.2f} < {tau}")
    return RouteDecision(base, f"base: retrieval score {max_s:.2f} ≥ {tau}")
