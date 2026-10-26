# Security & Privacy Policy

## 100% Local-First & Zero Telemetry Guarantee

**AgentGuard AI** is built on the strict principle that security tools must never become attack vectors or data leakage pipelines themselves.

### Architectural Privacy Guarantees:
1. **Zero External Network Requests**: AgentGuard AI does not transmit prompt logs, agent transcripts, tool arguments, or audit verdicts to any cloud server, third-party analytics, or remote API.
2. **Local Open-Weight Inference**: Semantic intent verification is performed either strictly in-browser or against a locally hosted **Google Gemma 2** / **Llama 3.2** model via an offline Ollama daemon (`http://localhost:11434`).
3. **No Persistent Session Storage Without Consent**: Tool audit trails and policy configurations are stored entirely in local memory and can be exported as local files on demand.
4. **Deterministic Gatekeeping**: Deterministic safety rules always override generative model output. An open model can provide contextual reasoning, but it cannot override a hard security block on dangerous operations.

## Reporting a Vulnerability

If you discover a security bypass, regex evasion, or vulnerability in AgentGuard AI, please report it directly via GitHub Security Advisories or open an issue marked with `[SECURITY]`.
