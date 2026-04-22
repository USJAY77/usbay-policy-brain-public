# AGENTS.md

## Review guidelines
- Do not disable validation or tests.
- Preserve fail-closed behavior.
- Never remove audit logging.
- Prefer minimal diffs.
- Do not modify secrets handling.
- Do not introduce logging of sensitive data.
- Keep Python import roots consistent with PYTHONPATH=$(pwd)/python.
- For CI failures, fix workflow/runtime alignment before changing application logic.
