"""Topology graph backed by the seeded legacy tables or optional Neo4j."""
from __future__ import annotations

import os
import json
from base64 import b64encode
from urllib.request import Request, urlopen

from .core import connect


CYPHER = {
    "blast_radius": """
        MATCH (p:PONPort {id:$port})-[:ON]->(l:OLT)
        OPTIONAL MATCH (s:Subscriber)-[:HAS_SERVICE]->(:CFS)-[:REALIZED_BY]->(:RFS)
                       -[:USES]->(:ONT)-[:TERMINATES_ON]->(p)
        WITH p, l, collect(DISTINCT s.id) AS subscribers
        OPTIONAL MATCH (a:Alarm)-[:RAISED_ON]->(target)
        WHERE target = p OR target = l
        RETURN l.id AS olt, subscribers,
               collect(DISTINCT {code:a.code, sev:a.sev, obj_ref:a.obj_ref}) AS alarms
    """,
    "path_to_core": """
        MATCH path=(o:ONT {id:$ont})-[:TERMINATES_ON]->(:PONPort)-[:ON]->(:OLT)
                   -[:HOUSED_IN]->(:CentralOffice)
        RETURN [n IN nodes(path) | n.id] AS hops
    """,
}

TOPOLOGY_IMPORT = """
    UNWIND $rows AS row
    MERGE (s:Subscriber {id:row.subscriber})
    MERGE (c:CFS {id:row.cfs})
    MERGE (r:RFS {id:row.rfs})
    MERGE (o:ONT {id:row.ont})
    MERGE (p:PONPort {id:row.port})
    MERGE (l:OLT {id:row.olt})
    MERGE (co:CentralOffice {id:row.co})
    MERGE (s)-[:HAS_SERVICE]->(c)
    MERGE (c)-[:REALIZED_BY]->(r)
    MERGE (r)-[:USES]->(o)
    MERGE (o)-[:TERMINATES_ON]->(p)
    MERGE (p)-[:ON]->(l)
    MERGE (l)-[:HOUSED_IN]->(co)
"""

ALARM_IMPORT = """
    UNWIND $rows AS row
    MERGE (a:Alarm {id:row.id})
    SET a.code = row.code, a.sev = row.sev, a.obj_ref = row.obj_ref
    WITH a, row
    OPTIONAL MATCH (target) WHERE (target:PONPort OR target:OLT) AND target.id = row.obj_ref
    FOREACH (_ IN CASE WHEN target IS NULL THEN [] ELSE [1] END |
        MERGE (a)-[:RAISED_ON]->(target))
"""


def _neo4j():
    if not os.getenv("NEO4J_URI"):
        return None
    from neo4j import GraphDatabase

    return GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "")),
    )


def _query_api(statement: str, parameters: dict | None = None, *, read: bool = False) -> list[dict]:
    url = os.environ["NEO4J_QUERY_API_URL"]
    credentials = f"{os.getenv('NEO4J_USER', 'neo4j')}:{os.environ['NEO4J_PASSWORD']}"
    headers = {
        "Authorization": "Basic " + b64encode(credentials.encode()).decode(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {"statement": statement, "parameters": parameters or {}}
    if read:
        payload["accessMode"] = "Read"
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urlopen(request, timeout=45) as response:
        result = json.load(response)
    if result.get("errors"):
        raise RuntimeError(f"Neo4j Query API rejected query: {result['errors'][0].get('code')}")
    data = result.get("data", {})
    return [dict(zip(data.get("fields", []), values)) for values in data.get("values", [])]


def _session(driver, *, read: bool = False):
    from neo4j import READ_ACCESS, WRITE_ACCESS

    return driver.session(database=os.getenv("NEO4J_DATABASE") or None,
                          default_access_mode=READ_ACCESS if read else WRITE_ACCESS)


def _source_rows() -> tuple[list[dict], list[dict]]:
    with connect("legacy") as c:
        topology = [dict(subscriber=r[0], cfs=f"CFS-{r[0]}", rfs=f"RFS-{r[4]}",
                         ont=r[4], port=r[5], olt=r[6], co=r[7]) for r in c.execute(
            "SELECT c.sbscr_ref, c.cpe_sn, c.mdl_cd, c.fw_ver, c.ont_id, "
            "o.pon_port_id, p.olt_id, l.co_nm FROM cpe_inv c "
            "JOIN ont_inv o ON o.ont_id=c.ont_id "
            "JOIN pon_port p ON p.pon_port_id=o.pon_port_id "
            "JOIN olt_inv l ON l.olt_id=p.olt_id")]
        alarms = [dict(id=str(r[0]), obj_ref=r[1], code=r[2], sev=r[3]) for r in c.execute(
            "SELECT alm_id, obj_ref, alm_cd, sev FROM alarm_log")]
    return topology, alarms


def sync_neo4j() -> dict[str, int]:
    """Idempotently import the synthetic topology needed by graph queries."""
    if not os.getenv("NEO4J_URI") and not os.getenv("NEO4J_QUERY_API_URL"):
        raise RuntimeError("NEO4J_URI is required to sync the topology")
    topology, alarms = _source_rows()
    if os.getenv("NEO4J_QUERY_API_URL"):
        for label in ("Subscriber", "CFS", "RFS", "ONT", "PONPort", "OLT", "CentralOffice", "Alarm"):
            _query_api(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
                       f"FOR (n:{label}) REQUIRE n.id IS UNIQUE")
        for start in range(0, len(topology), 200):
            _query_api(TOPOLOGY_IMPORT, {"rows": topology[start:start + 200]})
        if alarms:
            _query_api(ALARM_IMPORT, {"rows": alarms})
    else:
        driver = _neo4j()
        with driver:
            driver.verify_connectivity()
            with _session(driver) as session:
                for label in ("Subscriber", "CFS", "RFS", "ONT", "PONPort", "OLT", "CentralOffice", "Alarm"):
                    session.run(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
                                f"FOR (n:{label}) REQUIRE n.id IS UNIQUE").consume()
                for start in range(0, len(topology), 200):
                    session.execute_write(lambda tx, rows: tx.run(TOPOLOGY_IMPORT, rows=rows).consume(),
                                          topology[start:start + 200])
                if alarms:
                    session.execute_write(lambda tx: tx.run(ALARM_IMPORT, rows=alarms).consume())
    return {"topology_rows": len(topology), "alarms": len(alarms)}


def port_for_subscriber(subscriber_id: str) -> str | None:
    with connect("legacy") as c:
        r = c.execute("SELECT o.pon_port_id FROM cpe_inv c JOIN ont_inv o ON o.ont_id = c.ont_id WHERE c.sbscr_ref=?",
                      (subscriber_id,)).fetchone()
    return r[0] if r else None


def blast_radius(pon_port: str) -> dict:
    if os.getenv("NEO4J_QUERY_API_URL"):
        rows = _query_api(CYPHER["blast_radius"], {"port": pon_port}, read=True)
        rec = rows[0] if rows else None
        if rec is None:
            return {"pon_port": pon_port, "olt": None, "affected_count": 0,
                    "subscribers": [], "alarms": []}
        subscribers = sorted(s for s in rec["subscribers"] if s is not None)
        alarms = [a for a in rec["alarms"] if a["code"] is not None]
        return {"pon_port": pon_port, "olt": rec["olt"], "affected_count": len(subscribers),
                "subscribers": subscribers, "alarms": alarms}
    driver = _neo4j()
    if driver:
        with driver, _session(driver, read=True) as session:
            rec = session.run(CYPHER["blast_radius"], port=pon_port).single()
            if rec is None:
                return {"pon_port": pon_port, "olt": None, "affected_count": 0,
                        "subscribers": [], "alarms": []}
            subscribers = sorted(s for s in rec["subscribers"] if s is not None)
            alarms = [a for a in rec["alarms"] if a["code"] is not None]
            return {"pon_port": pon_port, "olt": rec["olt"], "affected_count": len(subscribers),
                    "subscribers": subscribers, "alarms": alarms}
    with connect("legacy") as c:
        subs = [r[0] for r in c.execute(
            "SELECT DISTINCT c.sbscr_ref FROM ont_inv o JOIN cpe_inv c ON c.ont_id = o.ont_id WHERE o.pon_port_id=?",
            (pon_port,))]
        olt = c.execute("SELECT olt_id FROM pon_port WHERE pon_port_id=?", (pon_port,)).fetchone()
        alarms = [dict(r) for r in c.execute("SELECT alm_cd AS code, sev, obj_ref FROM alarm_log WHERE obj_ref IN (?,?)",
                                             (pon_port, olt[0] if olt else ""))]
    return {"pon_port": pon_port, "olt": olt[0] if olt else None, "affected_count": len(subs),
            "subscribers": subs, "alarms": alarms}


def path_to_core(ont_id: str) -> list[str]:
    if os.getenv("NEO4J_QUERY_API_URL"):
        rows = _query_api(CYPHER["path_to_core"], {"ont": ont_id}, read=True)
        return rows[0]["hops"] if rows else []
    driver = _neo4j()
    if driver:
        with driver, _session(driver, read=True) as session:
            rec = session.run(CYPHER["path_to_core"], ont=ont_id).single()
            return rec["hops"] if rec else []
    with connect("legacy") as c:
        r = c.execute("SELECT o.ont_id, p.pon_port_id, p.olt_id, l.co_nm FROM ont_inv o JOIN pon_port p ON"
                      " p.pon_port_id = o.pon_port_id JOIN olt_inv l ON l.olt_id = p.olt_id WHERE o.ont_id=?",
                      (ont_id,)).fetchone()
    return list(r) if r else []
