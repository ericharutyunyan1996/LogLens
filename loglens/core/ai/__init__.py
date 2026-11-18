"""Optional AI assistant: configuration, redaction, prompt building and providers (no Qt here).

Principles (from user research): deterministic first, AI second; the model only sees what the user previewed;
sensitive values are redacted; every claim must cite the log lines it is based on.
"""
