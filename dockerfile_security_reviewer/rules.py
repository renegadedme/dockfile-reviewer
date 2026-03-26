from __future__ import annotations

import re
from collections.abc import Iterable

from .models import Finding, Instruction

SECRET_PATTERN = re.compile(r"(secret|token|password|passwd|api[_-]?key|access[_-]?key)", re.IGNORECASE)


def run_rules(instructions: Iterable[Instruction]) -> list[Finding]:
    instruction_list = list(instructions)
    findings: list[Finding] = []
    findings.extend(_check_base_image_pinning(instruction_list))
    findings.extend(_check_add_usage(instruction_list))
    findings.extend(_check_user_configuration(instruction_list))
    findings.extend(_check_secret_exposure(instruction_list))
    findings.extend(_check_package_installs(instruction_list))
    findings.extend(_check_remote_script_execution(instruction_list))
    return sorted(findings, key=lambda finding: (-_severity_rank(finding.severity), finding.line, finding.code))


def _check_base_image_pinning(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []

    for instruction in instructions:
        if instruction.keyword != "FROM":
            continue

        image = _extract_image_reference(instruction.value)
        if not image:
            continue

        if image.endswith(":latest"):
            findings.append(
                Finding(
                    code="DSR001",
                    title="Base image uses the latest tag",
                    severity="medium",
                    line=instruction.start_line,
                    message=f"The image `{image}` is not pinned to a stable version.",
                    recommendation="Pin to a specific version or digest, for example `python:3.12-slim`.",
                )
            )
            continue

        if "@sha256:" not in image and ":" not in image.rsplit("/", 1)[-1]:
            findings.append(
                Finding(
                    code="DSR009",
                    title="Base image is not pinned",
                    severity="low",
                    line=instruction.start_line,
                    message=f"The image `{image}` does not declare a tag or digest.",
                    recommendation="Use an explicit version tag or immutable digest to improve reproducibility.",
                )
            )
    return findings


def _check_add_usage(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []

    for instruction in instructions:
        if instruction.keyword != "ADD":
            continue
        findings.append(
            Finding(
                code="DSR002",
                title="ADD used instead of COPY",
                severity="medium",
                line=instruction.start_line,
                message="`ADD` has implicit behaviors that make Dockerfiles harder to reason about.",
                recommendation="Prefer `COPY` unless you explicitly need archive extraction or remote URL handling.",
            )
        )
    return findings


def _check_user_configuration(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []
    user_instructions = [instruction for instruction in instructions if instruction.keyword == "USER"]

    if not user_instructions:
        fallback_line = instructions[-1].start_line if instructions else 1
        findings.append(
            Finding(
                code="DSR003",
                title="Missing USER instruction",
                severity="high",
                line=fallback_line,
                message="The container will run as the image default user, which is often root.",
                recommendation="Create an unprivileged account and switch to it with `USER appuser`.",
            )
        )
        return findings

    last_user = user_instructions[-1]
    normalized = last_user.value.strip().split()[0].lower()
    if normalized in {"root", "0", "0:0"}:
        findings.append(
            Finding(
                code="DSR004",
                title="Container runs as root",
                severity="high",
                line=last_user.start_line,
                message="The final `USER` instruction resolves to root.",
                recommendation="Switch to a dedicated unprivileged user before the final runtime stage.",
            )
        )
    return findings


def _check_secret_exposure(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []

    for instruction in instructions:
        if instruction.keyword == "ENV":
            findings.extend(_env_secret_findings(instruction))
        if instruction.keyword == "ARG":
            findings.extend(_arg_secret_findings(instruction))

    return findings


def _env_secret_findings(instruction: Instruction) -> list[Finding]:
    tokens = instruction.value.replace("\\\n", " ").split()
    pairs: list[tuple[str, str | None]] = []

    if all("=" in token for token in tokens):
        for token in tokens:
            name, _, value = token.partition("=")
            pairs.append((name, value))
    elif len(tokens) >= 2:
        pairs.append((tokens[0], " ".join(tokens[1:])))

    findings: list[Finding] = []
    for name, value in pairs:
        if SECRET_PATTERN.search(name):
            findings.append(
                Finding(
                    code="DSR005",
                    title="Potential secret exposed through ENV",
                    severity="high",
                    line=instruction.start_line,
                    message=f"The variable `{name}` looks sensitive and is assigned in the Dockerfile.",
                    recommendation="Inject secrets at runtime with your orchestrator or secret manager instead of baking them into the image.",
                )
            )
        elif value and SECRET_PATTERN.search(value):
            findings.append(
                Finding(
                    code="DSR005",
                    title="Potential secret value baked into ENV",
                    severity="high",
                    line=instruction.start_line,
                    message="An ENV value appears to contain secret-like content.",
                    recommendation="Remove the hard-coded value and load it from a runtime secret source.",
                )
            )
    return findings


def _arg_secret_findings(instruction: Instruction) -> list[Finding]:
    name, _, value = instruction.value.partition("=")
    normalized_name = name.strip()
    if not normalized_name or not SECRET_PATTERN.search(normalized_name):
        return []

    severity = "high" if value.strip() else "medium"
    message = (
        f"The build argument `{normalized_name}` looks sensitive and has a default value."
        if value.strip()
        else f"The build argument `{normalized_name}` looks sensitive and may encourage secret injection during builds."
    )
    return [
        Finding(
            code="DSR006",
            title="Sensitive ARG detected",
            severity=severity,
            line=instruction.start_line,
            message=message,
            recommendation="Use build-time secret mounts or a secret manager instead of ARG for credentials.",
        )
    ]


def _check_package_installs(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []

    for instruction in instructions:
        if instruction.keyword != "RUN":
            continue

        command = instruction.value.lower()
        if "apt-get install" in command or "apt install" in command:
            if "--no-install-recommends" not in command:
                findings.append(
                    Finding(
                        code="DSR007",
                        title="APT install includes recommended packages",
                        severity="medium",
                        line=instruction.start_line,
                        message="The install command may pull unnecessary packages and enlarge the attack surface.",
                        recommendation="Add `--no-install-recommends` unless you intentionally need recommended packages.",
                    )
                )
            if "rm -rf /var/lib/apt/lists" not in command:
                findings.append(
                    Finding(
                        code="DSR008",
                        title="APT cache is not cleaned",
                        severity="low",
                        line=instruction.start_line,
                        message="Package metadata is left behind in the final image.",
                        recommendation="Remove `/var/lib/apt/lists/*` in the same RUN layer after installation.",
                    )
                )

        if "apk add" in command and "--no-cache" not in command:
            findings.append(
                Finding(
                    code="DSR010",
                    title="APK add runs without --no-cache",
                    severity="medium",
                    line=instruction.start_line,
                    message="The command may preserve package index data in the image.",
                    recommendation="Use `apk add --no-cache` to avoid storing package manager caches.",
                )
            )

    return findings


def _check_remote_script_execution(instructions: list[Instruction]) -> list[Finding]:
    findings: list[Finding] = []
    risky_pattern = re.compile(r"(curl|wget).*(\||>)\s*(sh|bash)", re.IGNORECASE)

    for instruction in instructions:
        if instruction.keyword != "RUN":
            continue
        if risky_pattern.search(instruction.value):
            findings.append(
                Finding(
                    code="DSR011",
                    title="Remote script piped into a shell",
                    severity="high",
                    line=instruction.start_line,
                    message="The Dockerfile downloads a remote script and executes it immediately.",
                    recommendation="Fetch the artifact separately, verify its checksum or signature, and execute a trusted local file instead.",
                )
            )
    return findings


def _extract_image_reference(value: str) -> str:
    tokens = value.split()
    if not tokens:
        return ""

    index = 0
    while index < len(tokens) and tokens[index].startswith("--"):
        index += 1

    return tokens[index] if index < len(tokens) else ""


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}[severity]

