from pathlib import Path

import yaml


VALID_ACTIONS = {
    "preserve",
    "pseudonymize",
    "redact",
}


MANDATORY_REDACT = {
    "PASSWORD",
    "BEARER_TOKEN",
    "JWT",
    "PRIVATE_KEY",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "AWS_SESSION_TOKEN",
    "API_KEY",
    "SESSION",
    "AUTH_CREDENTIAL",
    "DATABASE_PASSWORD",
    "PROVIDER_TOKEN",
    "GENERIC_SECRET",
}


VALID_GATE_STATES = {
    "PASS",
    "REVIEW",
    "BLOCKED",
}


VALID_GATE_RULES = {
    "PRESERVED_FINDING",
    "NO_FINDINGS",
}


DEFAULT_GATE_POLICY = {
    "PRESERVED_FINDING": "REVIEW",
    "NO_FINDINGS": "REVIEW",
}


DEFAULT_POLICY = {
    "GLOBAL": {
        "PASSWORD": "redact",
        "BEARER_TOKEN": "redact",
        "JWT": "redact",
        "PRIVATE_KEY": "redact",
        "AWS_ACCESS_KEY": "redact",
        "AWS_SECRET_KEY": "redact",
        "AWS_SESSION_TOKEN": "redact",
        "API_KEY": "redact",
        "SESSION": "redact",
        "AUTH_CREDENTIAL": "redact",
        "DATABASE_PASSWORD": "redact",
        "PROVIDER_TOKEN": "redact",
        "GENERIC_SECRET": "redact",
        "EMAIL": "pseudonymize",
        "PRIVATE_IP": "pseudonymize",
        "HOSTNAME": "pseudonymize",
        "MAC_ADDRESS": "pseudonymize",
        "CREDIT_CARD": "redact",
    },

    "GENERIC": {
        "USERNAME": "pseudonymize",
    },

    "BURP": {
        "USERNAME": "pseudonymize",
    },

    "WINDOWS": {
        "USERNAME": "preserve",
    },
}


class PolicyError(Exception):
    """Raised when a policy is invalid."""


def merge_policy(
    base: dict,
    override: dict,
) -> dict:

    merged = {
        profile: dict(rules)
        for profile, rules in base.items()
    }

    for profile, rules in override.items():

        if not isinstance(rules, dict):
            raise PolicyError(
                f"Policy section {profile} must be a mapping."
            )

        if profile not in merged:
            merged[profile] = {}

        merged[profile].update(
            rules
        )

    return merged


class Policy:

    def __init__(
        self,
        data: dict | None = None,
        gate: dict | None = None,
    ):

        self.data = merge_policy(
            DEFAULT_POLICY,
            data or {},
        )

        self.gate = dict(
            DEFAULT_GATE_POLICY
        )

        if gate:

            for rule, state in gate.items():

                normalized_rule = str(
                    rule
                ).upper()

                normalized_state = str(
                    state
                ).upper()

                self.gate[
                    normalized_rule
                ] = normalized_state

        self._validate()


    def _validate(self) -> None:

        for profile, rules in self.data.items():

            if not isinstance(rules, dict):
                raise PolicyError(
                    f"Policy section {profile} must be a mapping."
                )

            for category, action in rules.items():

                if action not in VALID_ACTIONS:
                    raise PolicyError(
                        "Invalid policy action "
                        f"{action!r} for "
                        f"{profile}.{category}."
                    )

        for category in MANDATORY_REDACT:

            action = self.data.get(
                "GLOBAL",
                {},
            ).get(
                category
            )

            if action != "redact":
                raise PolicyError(
                    "Mandatory secret rule "
                    f"{category} cannot be weakened."
                )

        for rule, state in self.gate.items():

            if rule not in VALID_GATE_RULES:
                raise PolicyError(
                    f"Unknown gate rule: {rule}"
                )

            if state not in VALID_GATE_STATES:
                raise PolicyError(
                    "Invalid gate state "
                    f"{state!r} for {rule}."
                )


    def resolve(
        self,
        *,
        profile: str,
        category: str,
        default_action: str,
    ) -> str:

        action, _reason = self.explain(
            profile=profile,
            category=category,
            default_action=default_action,
        )

        return action


    def explain(
        self,
        *,
        profile: str,
        category: str,
        default_action: str,
    ) -> tuple[str, str]:

        if category in MANDATORY_REDACT:

            return (
                "redact",
                "mandatory security rule",
            )

        profile_rules = self.data.get(
            profile,
            {},
        )

        if category in profile_rules:

            return (
                profile_rules[category],
                "profile policy",
            )

        global_rules = self.data.get(
            "GLOBAL",
            {},
        )

        if category in global_rules:

            return (
                global_rules[category],
                "global policy",
            )

        return (
            default_action,
            "detector default",
        )


    def gate_state(
        self,
        rule: str,
    ) -> str:

        normalized_rule = rule.upper()

        if normalized_rule not in VALID_GATE_RULES:
            raise PolicyError(
                f"Unknown gate rule: {normalized_rule}"
            )

        return self.gate[
            normalized_rule
        ]


    @classmethod
    def from_file(
        cls,
        path: str | Path,
    ) -> "Policy":

        policy_path = Path(
            path
        )

        try:

            raw = yaml.safe_load(
                policy_path.read_text(
                    encoding="utf-8"
                )
            )

        except OSError as exc:

            raise PolicyError(
                f"Could not read policy file: {policy_path}"
            ) from exc

        except yaml.YAMLError as exc:

            raise PolicyError(
                f"Invalid YAML policy: {policy_path}"
            ) from exc

        if raw is None:
            raw = {}

        if not isinstance(raw, dict):

            raise PolicyError(
                "Policy root must be a mapping."
            )

        raw = dict(
            raw
        )

        gate = raw.pop(
            "GATE",
            {},
        )

        if gate is None:
            gate = {}

        if not isinstance(gate, dict):

            raise PolicyError(
                "GATE section must be a mapping."
            )

        return cls(
            data=raw,
            gate=gate,
        )
