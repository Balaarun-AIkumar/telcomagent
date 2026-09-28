# Neo4j Aura and Langfuse Cloud demo setup

## Neo4j Aura

An optional AuraDB instance can hold the synthetic topology. The synthetic topology is imported from the local SQLite demo database. The app's two graph queries, blast radius and ONT path to core, use Aura through its HTTPS Query API. This work computer can reach Aura over HTTPS; its Python Bolt TLS handshake fails, so `.env` sets `NEO4J_QUERY_API_URL`.

The ignored `.env` contains `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`, and `NEO4J_QUERY_API_URL`. Keep the credential download private and out of Git. No credential is stored in source code.

After reseeding the demo data, run:

```powershell
# Run from your project folder
powershell -ExecutionPolicy Bypass -File .\sync-neo4j.ps1
```

The importer uses `MERGE`, so rerunning it does not duplicate current nodes or relationships. It does not remove data from a previous seed or other applications in the Aura instance. The current demo graph contains 2,000 subscriber topology rows and one alarm; Aura reports 8,651 nodes and 8,649 relationships. A live query returned 24 subscribers on `PON-01-01`, the `LOS` alarm, and the path `ONT-00000 → PON-01-01 → OLT-01 → CO-SOMERVILLE`. The `sync-neo4j.ps1` command was run a second time successfully.

## Langfuse Cloud

The Langfuse project is on `https://cloud.langfuse.com`. Its keys and base URL are configured in the ignored `.env`; the app exports OpenTelemetry traces using:

```dotenv
LANGFUSE_PUBLIC_KEY=<your public key>
LANGFUSE_SECRET_KEY=<your secret key>
LANGFUSE_BASE_URL=https://cloud.langfuse.com
```

The app derives the Basic authentication header and sends spans to `/api/public/otel/v1/traces`. The existing `LANGFUSE_OTLP_ENDPOINT` and `LANGFUSE_BASIC_AUTH` pair is also supported. Never commit `.env` or copy the keys into a public issue or chat.

An `integration.langfuse.check` synthetic span was sent successfully and appeared in the project's **Tracing** page. Start the app with `powershell -ExecutionPolicy Bypass -File .\start.ps1`, ask a question in the UI, then refresh that page to see the new traces. Trace export uses a batch processor, so a trace can appear a few seconds after the request. The app scrubs span attributes before export; Langfuse still receives operational trace metadata, so use only the intended cloud project.
