# Contributing to AgentGuard AI

Thank you for your interest in contributing to **AgentGuard AI**! We welcome community contributions to expand threat signatures, enhance semantic auditing heuristics, and harden autonomous agent security.

## Principles & Requirements

1. **100% Local-First & Zero Telemetry**:
   - Any proposed change must strictly preserve user privacy. Under no circumstances should agent logs, prompt contexts, or tool arguments be transmitted to external servers or telemetry collectors.
2. **Deterministic Rules Over Generative Fallbacks**:
   - High-severity attack vectors (e.g. `rm -rf`, path traversal, SQL drops) must always have a deterministic rule signature. Generative models (e.g. Gemma 2) are used for semantic reasoning on ambiguous context, but deterministic rules provide hard execution blocks.
3. **Automated Test Coverage**:
   - Every new signature or feature must include a corresponding automated unit test in `test_engine.js`.
4. **Performance Benchmark**:
   - Tier 1 inspection must execute in under `< 2.0 ms` to avoid introducing latency bottlenecks into agent workflows.

## Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/AaryanKumarSingh136/agentguard-ai.git
   cd agentguard-ai
   ```
2. Run the test suite:
   ```bash
   node test_engine.js
   ```
3. Add your signature or logic to `app.js` under the appropriate category in `SIGNATURES`.
4. Add verification cases to `test_engine.js`.
5. Ensure all tests pass with 0 failures:
   ```bash
   npm test
   ```
6. Submit a clean pull request with a descriptive title and rationale.
