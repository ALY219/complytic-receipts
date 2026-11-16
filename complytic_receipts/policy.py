"""Deterministic Evaluation Gate.

Evaluated before the T=0 intent receipt is sealed. Rules are hard-coded and
versioned by policy_hash; the verdict, rule id and policy hash are sealed
inside the signed intent receipt so the chain proves which rule permitted
(or denied) each statement. Denials fail closed and are still signed and chained.
"""
from .canonical import canon, sha256_hex


class PolicyViolationError(Exception):
    """Raised when the gate denies a statement. Nothing executes."""


class PolicyGate:
    # Hard-coded invariants. Edit here; the hash changes and every new
    # receipt records which policy version was in force.
    RULES = {
        "deny_destructive_ddl": ["DROP TABLE", "DROP DATABASE", "TRUNCATE"],
        "deny_schema_mutation": ["ALTER TABLE"],
    }

    def __init__(self):
        self.policy_hash = sha256_hex(canon(self.RULES))

    def evaluate(self, sql, params=None):
        """Returns (allowed, rule_id, reason). Deterministic, no I/O."""
        upper = sql.upper()
        for rule_id, patterns in self.RULES.items():
            for pat in patterns:
                if pat in upper:
                    return False, rule_id, f"pattern {pat!r} denied by policy"
        return True, "default-allow", "no rule matched"