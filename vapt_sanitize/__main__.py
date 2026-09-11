import argparse
import sys
from collections import Counter
from pathlib import Path

from . import __version__

from .clipboard import (
    ClipboardError,
    read_clipboard,
    verify_clipboard,
    write_clipboard,
)
from .context import ContextEngine
from .engine import sanitize
from .engagement import EngagementError, EngagementVault
from .integrations.burp import determine_security_gate
from .llm.dispatch import LLMDispatchBlocked
from .llm.handoff import build_authorized_prompt
from .llm.models import LLMRequestError
from .policy import Policy, PolicyError


AI_TASKS = {
    "analyze-security": "ANALYZE_SECURITY",
    "explain-response": "EXPLAIN_RESPONSE",
    "find-attack-surface": "FIND_ATTACK_SURFACE",
    "suggest-next-tests": "SUGGEST_NEXT_TESTS",
    "custom": "CUSTOM",
}


PROFILE_SOURCES = {
    "GENERIC": "Generic security testing input",
    "NMAP": "Nmap enumeration",
    "BURP": "Burp HTTP data",
    "GOBUSTER": "Gobuster enumeration",
    "NUCLEI": "Nuclei scan",
    "WINDOWS": "Windows enumeration",
    "LINUX": "Linux enumeration",
    "AWS": "AWS enumeration",
    "SECRETS": "Secrets / credentials review",
    "PII": "PII / personal data review",
}


def handle_engagement_command(argv: list[str]) -> bool:
    if not argv or argv[0] != "engagement":
        return False

    parser = argparse.ArgumentParser(
        prog="python -m vapt_sanitize engagement",
        description="Manage encrypted engagement pseudonym mappings.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Create a new encrypted engagement mapping vault.",
    )
    init_parser.add_argument("engagement_id")

    show_parser = subparsers.add_parser(
        "show",
        help="Show the local placeholder-to-real-value mapping.",
    )
    show_parser.add_argument("engagement_id")

    resolve_parser = subparsers.add_parser(
        "resolve",
        help="Resolve one or more placeholders to local real values.",
    )
    resolve_parser.add_argument("engagement_id")
    resolve_parser.add_argument("placeholders", nargs="+")

    args = parser.parse_args(argv[1:])

    try:
        if args.command == "init":
            vault = EngagementVault.create(args.engagement_id)
            print(f"[+] Engagement created: {vault.engagement_id}")
            print(f"[+] Encrypted mapping: {vault.mapping_path}")
            print("[+] Redacted secrets are never stored in the mapping vault.")
            return True

        vault = EngagementVault.open(args.engagement_id)

        if args.command == "show":
            entries = vault.entries()
            print(f"Engagement: {vault.engagement_id}")
            if not entries:
                print("(mapping is empty)")
                return True

            print(f"{'PLACEHOLDER':<30} REAL VALUE")
            print(f"{'-' * 28:<30} {'-' * 40}")
            for entry in entries:
                originals = " | ".join(entry["originals"])
                print(f"{entry['placeholder']:<30} {originals}")
            return True

        if args.command == "resolve":
            for placeholder in args.placeholders:
                originals = vault.resolve(placeholder)
                print(f"{placeholder} -> {' | '.join(originals)}")
            return True

    except EngagementError as exc:
        parser.error(str(exc))

    return True


def read_input(
    input_path: str | None,
) -> tuple[str, str]:

    if input_path is None or input_path == "-":

        if sys.stdin.isatty():
            raise ValueError(
                "No input provided. "
                "Specify a file, pipe stdin, "
                "or use --clipboard."
            )

        text = sys.stdin.read()

        if not text:
            raise ValueError(
                "stdin is empty."
            )

        return text, "stdin"

    path = Path(input_path)

    if not path.exists():
        raise ValueError(
            f"File not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Input is not a file: {path}"
        )

    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return text, str(path)


def ai_source_label(
    profile: str,
    explicit_source: str | None,
) -> str:

    if explicit_source is not None:

        explicit_source = explicit_source.strip()

        if explicit_source:
            return explicit_source

    return PROFILE_SOURCES.get(
        profile,
        "Security testing input",
    )


def main():
    if handle_engagement_command(sys.argv[1:]):
        return

    parser = argparse.ArgumentParser(
        description=(
            "VAPT-Sanitize - sanitize pentest data "
            "before sending it to an LLM"
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"VAPT Sanitizer {__version__}",
    )


    parser.add_argument(
        "input",
        nargs="?",
        help=(
            "Input file. Use '-' or omit it "
            "to read from stdin."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Output file. With --ai-prompt, writes the "
            "AI-ready prompt instead of raw sanitized content."
        ),
    )

    parser.add_argument(
        "--clipboard",
        action="store_true",
        help=(
            "Read from clipboard and replace it with sanitized content. "
            "With --ai-prompt, replace it with the AI-ready prompt."
        ),
    )

    parser.add_argument(
        "--ai-clipboard",
        action="store_true",
        help=(
            "Copy the AI-ready prompt to the clipboard while reading "
            "input from a file or stdin. Requires --ai-prompt."
        ),
    )

    parser.add_argument(
        "--ai-prompt",
        action="store_true",
        help=(
            "After sanitization and Security Gate checks, build a "
            "provider-neutral AI-ready prompt. No network request is made."
        ),
    )

    parser.add_argument(
        "--task",
        choices=list(AI_TASKS),
        default="analyze-security",
        help=(
            "AI handoff task. Used only with --ai-prompt."
        ),
    )

    parser.add_argument(
        "--question",
        help=(
            "Optional analyst question for the AI prompt. Required when "
            "--task custom is selected."
        ),
    )

    parser.add_argument(
        "--source",
        help=(
            "Optional source label stored in the AI prompt, for example "
            "'Nmap enumeration'. Defaults from the detected/selected profile."
        ),
    )

    parser.add_argument(
        "--review-approved",
        action="store_true",
        help=(
            "Explicitly approve an AI handoff whose Security Gate state "
            "is REVIEW. Has no effect on BLOCKED."
        ),
    )

    parser.add_argument(
        "--profile",
        choices=[
            "auto",
            "generic",
            "nmap",
            "burp",
            "gobuster",
            "nuclei",
            "windows",
            "linux",
            "aws",
            "secrets",
            "pii",
        ],
        default="auto",
        help="Sanitization profile",
    )

    parser.add_argument(
        "--policy",
        help="YAML policy file",
    )

    parser.add_argument(
        "--engagement",
        help=(
            "Use an encrypted engagement-scoped pseudonym mapping vault. "
            "Create it first with: engagement init <ID>."
        ),
    )

    parser.add_argument(
        "--explain",
        action="store_true",
        help="Explain sanitization decisions",
    )

    args = parser.parse_args()

    if args.clipboard and args.input is not None:
        parser.error(
            "--clipboard cannot be used with an input file."
        )

    if args.ai_clipboard and not args.ai_prompt:
        parser.error(
            "--ai-clipboard requires --ai-prompt."
        )

    if args.review_approved and not args.ai_prompt:
        parser.error(
            "--review-approved requires --ai-prompt."
        )

    if args.output and args.ai_clipboard:
        parser.error(
            "Choose either --output or --ai-clipboard for AI prompt output."
        )

    if args.task == "custom" and not args.ai_prompt:
        parser.error(
            "--task custom requires --ai-prompt."
        )

    # ---------------------------------------------------------
    # INPUT
    # ---------------------------------------------------------

    try:

        if args.clipboard:
            text = read_clipboard()
            source = "clipboard"

            if not text:
                raise ValueError(
                    "Clipboard is empty."
                )

        else:
            text, source = read_input(
                args.input
            )

    except (
        ValueError,
        ClipboardError,
    ) as exc:
        parser.error(str(exc))

    # ---------------------------------------------------------
    # POLICY
    # ---------------------------------------------------------

    try:

        policy = (
            Policy.from_file(args.policy)
            if args.policy
            else Policy()
        )

    except PolicyError as exc:
        parser.error(str(exc))

    # ---------------------------------------------------------
    # ENGAGEMENT VAULT
    # ---------------------------------------------------------

    mapping_store = None

    if args.engagement:
        try:
            mapping_store = EngagementVault.open(args.engagement)
        except EngagementError as exc:
            parser.error(str(exc))

    # ---------------------------------------------------------
    # CONTEXT
    # ---------------------------------------------------------

    context_engine = ContextEngine()
    context_blocks = context_engine.analyze(text)

    # ---------------------------------------------------------
    # SANITIZATION
    # ---------------------------------------------------------

    if args.profile == "auto":

        (
            sanitized,
            findings,
            _,
            profile_result,
        ) = sanitize(
            text,
            policy=policy,
            mapping_store=mapping_store,
        )

        selected_profile = profile_result.name

    else:

        selected_profile = args.profile.upper()

        (
            sanitized,
            findings,
            _,
            profile_result,
        ) = sanitize(
            text,
            profile=selected_profile,
            policy=policy,
            mapping_store=mapping_store,
        )

    # ---------------------------------------------------------
    # AI HANDOFF
    # ---------------------------------------------------------

    if args.ai_prompt:

        security_gate, gate_reason = (
            determine_security_gate(
                findings,
                sanitized=sanitized,
                profile=selected_profile,
                policy=policy,
            )
        )

        if security_gate == "BLOCKED":
            print(
                "[!] AI handoff BLOCKED: "
                + gate_reason,
                file=sys.stderr,
            )
            raise SystemExit(3)

        if (
            security_gate == "REVIEW"
            and not args.review_approved
        ):
            print(
                "[!] AI handoff requires REVIEW: "
                + gate_reason,
                file=sys.stderr,
            )
            print(
                "[!] Review the sanitized output, then rerun with "
                "--review-approved if you explicitly approve the handoff.",
                file=sys.stderr,
            )
            raise SystemExit(3)

        try:

            ai_prompt = build_authorized_prompt(
                sanitized,
                task=AI_TASKS[args.task],
                gate_state=security_gate,
                review_approved=args.review_approved,
                policy=policy,
                profile=selected_profile,
                source=ai_source_label(
                    selected_profile,
                    args.source,
                ),
                question=args.question,
                policy_name=(
                    args.policy
                    if args.policy
                    else "built-in defaults"
                ),
            )

        except (
            LLMDispatchBlocked,
            LLMRequestError,
        ) as exc:
            print(
                f"[!] AI handoff failed: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(3)

        if args.clipboard or args.ai_clipboard:

            try:
                write_clipboard(ai_prompt)

                verify_clipboard(
                    ai_prompt
                )

            except ClipboardError as exc:
                parser.error(
                    f"Could not safely update clipboard: {exc}"
                )

            print(
                "[+] AI-ready prompt copied to clipboard and verified.",
                file=sys.stderr,
            )

        elif args.output:

            output_path = Path(args.output)

            output_path.write_text(
                ai_prompt,
                encoding="utf-8",
            )

            print(
                f"[+] AI-ready prompt file: {output_path}",
                file=sys.stderr,
            )

        else:

            sys.stdout.write(
                ai_prompt
            )

        print(
            f"[+] Security Gate: {security_gate}",
            file=sys.stderr,
        )

        print(
            f"[+] Profile: {selected_profile}",
            file=sys.stderr,
        )

        if mapping_store is not None:
            print(
                f"[+] Engagement: {mapping_store.engagement_id}",
                file=sys.stderr,
            )

        print(
            "[+] No network communication was performed.",
            file=sys.stderr,
        )

        return

    # ---------------------------------------------------------
    # CLIPBOARD WRITE-BACK
    # ---------------------------------------------------------

    if args.clipboard:

        try:
            write_clipboard(sanitized)

            verify_clipboard(
                sanitized
            )

        except ClipboardError as exc:
            parser.error(
                f"Could not safely update clipboard: {exc}"
            )

        print(
            "[+] Clipboard sanitized and verified."
        )
    # ---------------------------------------------------------
    # FILE / STDOUT OUTPUT
    # ---------------------------------------------------------

    elif args.output:

        output_path = Path(args.output)

        output_path.write_text(
            sanitized,
            encoding="utf-8",
        )

        print(
            f"[+] Sanitized file: {output_path}"
        )

    else:

        print(sanitized)

    # ---------------------------------------------------------
    # REPORT
    # ---------------------------------------------------------

    print()
    print("=== VAPT-SANITIZE REPORT ===")

    print(
        f"Input: {source}"
    )

    print(
        f"Global profile: {selected_profile}"
    )

    if args.profile == "auto":

        print(
            f"Global confidence: "
            f"{profile_result.confidence:.0%}"
        )

    section_profiles = [
        block.profile
        for block in context_blocks
    ]

    unique_profiles = set(section_profiles)

    if len(unique_profiles) > 1:
        document_type = "MIXED"

    elif section_profiles:
        document_type = section_profiles[0]

    else:
        document_type = selected_profile

    print(
        f"Document type: {document_type}"
    )

    print()
    print("Detected sections:")

    section_counts = Counter(
        section_profiles
    )

    for profile, count in section_counts.most_common():

        print(
            f"  {profile}: {count} block(s)"
        )

    print()

    if args.policy:

        print(
            f"Policy: {args.policy}"
        )

    else:

        print(
            "Policy: built-in defaults"
        )

    if mapping_store is not None:
        print(
            f"Engagement: {mapping_store.engagement_id}"
        )

    print()
    print(
        f"Findings detected: {len(findings)}"
    )

    for finding in findings:

        print(
            f"  [{finding.severity.upper()}] "
            f"{finding.category} "
            f"-> {finding.replacement}"
        )

        if args.explain:

            print(
                f"      Profile: {finding.profile}"
            )

            print(
                f"      Action: {finding.action}"
            )

            print(
                f"      Reason: {finding.reason}"
            )


if __name__ == "__main__":
    main()
