# Demo walkthrough

## Start

From the project folder, run:

```powershell
.venv\Scripts\python -m switchboard.cli --offline --demo serve gateway
```

Open http://127.0.0.1:8000/. To use the configured cloud adapters instead, run `start.ps1` after starting the Permit PDP. The offline path is sufficient for the security demonstration and costs no API calls.

## Show the story in this order

1. Select **Maya** and ask for the Wi-Fi password at **14 Elm St**. Explain that chat receives a reference, never the password. Click the reveal card; the UI shows the synthetic credential briefly.
2. Select **Raj** and ask the same question. He can support the customer but cannot reveal credentials. Show the safe reset alternative.
3. As Raj, request a password reset for **S-88123**. Explain that a model response or the word "confirmed" cannot approve the write. Click the confirmation card.
4. Close **WO-1042**, ask as Maya again, and show the denial. Reopen the order afterwards. An old token or previous conversation does not preserve revoked access.
5. Select **Priya** and use the outage scenario. Show three evidence sources: topology, device status, and procedure. No ticket or visit is automatically created.
6. Ask Maya how to replace an ONT. Open a citation and explain permitted documents, latest revision and heading-based retrieval.
7. Ask Maya how many customers are in **02139**. She sees her assigned customer; Raj sees the broader permitted count. Same postcode does not mean same authorization.
8. After a customer question as Maya, use the **follow-up** button in the same session. The last subject is reused, but permissions run again.
9. Expand trace details and open Observability. Explain the difference between tool evidence, policy reasons and audit records. Do not show `.env` during a screen share.

## Code tour (five files first)

- `gateway.py`: request identity and the separate reveal/confirmation endpoints.
- `orchestrator.py`: six intents, fixed plans and bounded execution.
- `tools.py`: input schemas and mandatory authorization.
- `policy.py`: roles, relationships and live context.
- `tests/test_regressions.py`: exact examples of mistakes the code prevents.

Then show `rag.py`, `text2sql.py`, and the evaluation dataset if asked.

## Honest explanation of the LLM

Without credentials the router is deterministic. With Gemini configured it can understand paraphrases, and SQL generation can use the model when no template matches. A validated intent chooses a Python plan. The response reports `routing_source`; a `gen_ai.generate` span is evidence that a model call was attempted. Failed or invalid calls fall back to rules. Mocked tests prove adapter boundaries, not live model accuracy.

## What not to claim

The demo persona selector is not enterprise login, the on-site card is not real MFA, hash vectors are not neural embeddings, and the hash-chained SQLite audit is not administrator-proof. A2A/ADK/MCP are optional examples, not a fleet powering every question. No Kubernetes deployment or nightly calibrated GEval job exists.
