from __future__ import annotations

from .models import Instruction


def parse_dockerfile(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    buffer: list[str] = []
    start_line: int | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()

        if not buffer:
            if not stripped or stripped.startswith("#"):
                continue
            buffer = [raw_line.rstrip()]
            start_line = line_number
        else:
            buffer.append(raw_line.rstrip())

        if stripped.endswith("\\"):
            continue

        instruction = _build_instruction(buffer, start_line or line_number)
        if instruction is not None:
            instructions.append(instruction)
        buffer = []
        start_line = None

    if buffer:
        instruction = _build_instruction(buffer, start_line or 1)
        if instruction is not None:
            instructions.append(instruction)

    return instructions


def _build_instruction(lines: list[str], start_line: int) -> Instruction | None:
    raw = "\n".join(lines).strip()
    if not raw:
        return None

    parts = raw.split(None, 1)
    keyword = parts[0].upper()
    value = parts[1].strip() if len(parts) > 1 else ""
    return Instruction(keyword=keyword, value=value, start_line=start_line, raw=raw)

