# Dockerfile Security Reviewer

Dockerfile Security Reviewer is a small CLI that scans Dockerfiles for common security and maintainability mistakes, then explains what to fix in plain language. It is designed to be useful on its own with a deterministic rules engine, while leaving room for optional LLM-assisted explanations and rewrite suggestions.

## What it checks

- unpinned or `latest` base images
- `ADD` where `COPY` is usually safer
- missing `USER` instructions
- containers configured to run as `root`
- likely secrets committed through `ENV` or `ARG`
- package manager usage that increases image size or attack surface
- shell pipes that download and execute remote scripts

## Quick start

```bash
python3 -m dockerfile_security_reviewer samples/insecure.Dockerfile
```

Or install the package locally and use the CLI entry point:

```bash
python3 -m pip install -e .
dockerfile-reviewer samples/insecure.Dockerfile
```

## CLI usage

```bash
python3 -m dockerfile_security_reviewer path/to/Dockerfile
python3 -m dockerfile_security_reviewer path/to/Dockerfile --format json
python3 -m dockerfile_security_reviewer path/to/Dockerfile --fail-on medium
python3 -m dockerfile_security_reviewer path/to/Dockerfile --explain-with-openai
```

### Options

- `--format text|json`: choose human-readable or machine-readable output
- `--fail-on low|medium|high`: exit with status `1` when findings meet or exceed the threshold
- `--explain-with-openai`: append an LLM-generated summary and a suggested rewritten Dockerfile
- `--openai-model`: override the default model used for explanation

## Example output

```text
Dockerfile review for samples/insecure.Dockerfile
Found 7 issues: 2 high, 4 medium, 1 low

[HIGH] DSR005 line 5: Potential secret exposed through ENV
  The variable `AWS_SECRET_ACCESS_KEY` looks sensitive and is assigned in the Dockerfile.
  Fix: Inject secrets at runtime with your orchestrator or secret manager instead of baking them into the image.

[MEDIUM] DSR001 line 1: Base image uses the latest tag
  The image `python:latest` is not pinned to a stable version.
  Fix: Pin to a specific version or digest, for example `python:3.12-slim`.
```

## Optional OpenAI explanation

The core reviewer works without external services. If you want a natural-language summary of the findings and a suggested rewritten Dockerfile, install the optional dependency and provide an API key:

```bash
python3 -m pip install -e .[openai]
export OPENAI_API_KEY=your_key_here
python3 -m dockerfile_security_reviewer samples/insecure.Dockerfile --explain-with-openai
```

If the OpenAI package is not installed or the API key is missing, the CLI will explain what is needed instead of failing silently.

## Project layout

```text
dockerfile_security_reviewer/
  analyzer.py
  cli.py
  llm.py
  models.py
  parser.py
  reporting.py
  rules.py
samples/
tests/
```

## Running tests

```bash
python3 -m unittest discover -s tests -v
```

## Continuous integration

The repository includes a small GitHub Actions workflow that runs the unit test suite on every push and pull request.

## Why this project works well on GitHub

It has a clear problem statement, a useful CLI, deterministic test coverage, realistic sample inputs, and an optional AI layer that improves the developer experience instead of replacing the core logic.
