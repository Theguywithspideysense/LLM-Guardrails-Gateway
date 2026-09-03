# Contributing

1. Create a virtual environment and install `requirements-dev.txt`.
2. Make a focused change. Keep detection and redaction aligned by using shared findings.
3. Add a regression test when fixing a security or behavior bug. Model-dependent tests must mock Ollama.
4. Run `python -m pytest -q` and `node --test tests/dashboard.test.cjs`.
5. Explain the observable behavior change and any tradeoffs in your pull request.

Keep real credentials, prompts containing personal data, generated logs, and environments out of commits. Do not change an error path to silently allow generation. Update the README when changing policy semantics, supported data types, or environment settings.
