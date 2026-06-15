"""Generation — Day 4.

Claude Sonnet 4.6 produces a STRUCTURED, CITED answer over retrieved chunks:
severity, exploitation status, affected products, remediation — each claim tied to a CVE id.
Pydantic schema for the structured output; Langfuse traces the call.
"""
