from dataclasses import dataclass

@dataclass
class MetaBadges:
    rbac_ok: bool
    dp_epsilon: float | None
    audit_verifiable: bool
    sources_count: int
    policy_version: str
    build_version: str

    def as_badge_row(self) -> str:
        rbac = "RBAC ✅" if self.rbac_ok else "RBAC ⛔"
        dp = f"DP ε={self.dp_epsilon:.2f}" if self.dp_epsilon is not None else "DP n/a"
        return f"{rbac} | {dp} | Audit verifiable | Sources #{self.sources_count} | Policy {self.policy_version}"
