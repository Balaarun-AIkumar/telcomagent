"""Containerized MCP servers (streamable HTTP at /mcp). Each is a resource server: validates an audience-bound
JWT (aud=mcp-<name>) and routes through tools.call_tool, so Permit is re-checked here too (defense in depth).
Run: python -m switchboard.mcp_servers provisioning --port 9001   (requires the `mcp` extra)."""
import argparse

from . import auth, tools
from .context import current_principal

SERVERS = {
    "provisioning": ["find_subscriber", "query_provisioning", "get_work_orders", "trigger_psk_reset"],
    "acs": ["get_device_status", "get_wifi_config", "create_credential_reveal_grant", "reboot_device"],
    "ticketing": ["search_tickets", "get_ticket", "create_ticket", "add_note"],
    "knowledge": ["search_procedures", "get_document_section"],
    "topology": ["blast_radius", "path_to_core", "find_mop_for"],
}


def build(name: str):
    from mcp.server.fastmcp import Context, FastMCP
    from mcp.types import ToolAnnotations

    srv = FastMCP(f"mcp-{name}", stateless_http=True)

    def make(tool: tools.Tool):
        def handler(args: dict, ctx: Context) -> dict:
            try:
                req = ctx.request_context.request
                token = req.headers.get("authorization", "").removeprefix("Bearer ").strip()
                p = auth.principal_from_token(token, audience=f"mcp-{name}")
            except Exception:
                return {"status": "denied", "reason_code": "UNAUTHENTICATED"}
            tok = current_principal.set(p)
            prev = tools.authorized_subjects.set(set())
            try:
                return tools.call_tool(tool.name, args)
            finally:
                tools.authorized_subjects.reset(prev)
                current_principal.reset(tok)

        return handler

    for tname in SERVERS[name]:
        t = tools.TOOLS[tname]
        srv.add_tool(make(t), name=t.name, description=t.description or t.name.replace("_", " "),
                     annotations=ToolAnnotations(readOnlyHint=t.read_only, destructiveHint=t.destructive))

    @srv.custom_route("/healthz", methods=["GET"])
    async def healthz(_):
        from starlette.responses import JSONResponse

        return JSONResponse({"ok": True})

    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("server", choices=list(SERVERS))
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    s = build(a.server)
    s.settings.host, s.settings.port = "0.0.0.0", a.port
    s.run(transport="streamable-http")
