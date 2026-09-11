from .anonymizer import Anonymizer
from .context import ContextEngine
from .detectors import detect
from .policy import Policy
from .profiles import detect_profile
from .tool_metadata import finding_is_protected_tool_metadata


def sanitize(
    text: str,
    profile: str | None = None,
    policy: Policy | None = None,
    mapping_store=None,
):
    if policy is None:
        policy = Policy()

    if mapping_store is not None:
        mapping_store.begin_session()

    try:
        context_engine = ContextEngine()
        context_blocks = context_engine.analyze(text)

        global_profile_result = detect_profile(text)

        anonymizer = Anonymizer(
            mapping_store=mapping_store,
        )
        findings = []

        for block in context_blocks:

            selected_profile = (
                profile
                if profile is not None
                else block.profile
            )

            block_findings = detect(
                block.text,
                profile=selected_profile,
                policy=policy,
            )

            block_findings = [
                finding
                for finding in block_findings
                if not finding_is_protected_tool_metadata(
                    text=block.text,
                    profile=selected_profile,
                    category=finding.category,
                    start=finding.start,
                    end=finding.end,
                )
            ]

            for finding in block_findings:

                finding.start += block.start
                finding.end += block.start

                if finding.replace_start is not None:
                    finding.replace_start += block.start

                if finding.replace_end is not None:
                    finding.replace_end += block.start

            findings.extend(block_findings)

        findings.sort(
            key=lambda finding: finding.start
        )

        sanitized = anonymizer.sanitize(
            text,
            findings,
        )

        if mapping_store is not None:
            mapping_store.save()

        return (
            sanitized,
            findings,
            anonymizer.mapping,
            global_profile_result,
        )

    finally:
        if mapping_store is not None:
            mapping_store.end_session()
