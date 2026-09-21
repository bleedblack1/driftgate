# Changelog

## 0.1.0 (unreleased)

First release.

- Security regression gate: runs an attack corpus against an LLM agent,
  compares rates to a committed baseline, and fails CI when they get worse.
- Provider-agnostic. Any OpenAI-compatible endpoint out of the box; LiteLLM as
  an optional extra for Bedrock, Vertex and Azure.
- Instrumentation at the tool boundary, so assertions see tool calls, their
  arguments, and outbound requests rather than only the final text.
- Statistical gate: one-sided Fisher exact with Benjamini-Hochberg correction
  across the suite, so a suite of cases does not raise false alarms by volume.
- Utility control alongside the security score, so the gate cannot be passed by
  making the agent refuse everything.
- Tool roles, so the built-in corpus works against any toolkit.
- Coverage accounting: a case that cannot run is never reported as a pass.
- On-disk response cache, with per-sample keying that preserves measured rates.
- Local dashboard (`driftgate ui`) with transcript drill-down.

### Known limitations

- Not yet exercised against a live commercial model. All verification to date
  is against a local OpenAI-compatible test server.
- The LiteLLM backend is implemented but has not been run end to end.
