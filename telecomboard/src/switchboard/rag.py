"""RAG over legacy docs: MOP-aware parent/child chunking, injection quarantine, permission-aware hybrid retrieval (RRF)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import llm
from .core import connect
from .redaction import injection_score

QUARANTINE_AT = 0.5


def load(path: Path) -> tuple[dict, str]:
    if path.suffix.lower() == ".pdf":  # born-digital PDFs via LangChain loader when installed
        from langchain_community.document_loaders import PyMuPDFLoader

        pages = PyMuPDFLoader(str(path)).load()
        meta = {"doc_id": path.stem, "family": path.stem, "title": path.stem, "revision": 1, "effective_date": "",
                "vendor": "", "model": "*", "firmware_range": "*", "classification": "internal",
                "source_kind": "born_digital"}
        return meta, "\n".join(p.page_content for p in pages)
    head, _, body = path.read_text(encoding="utf-8").partition("\n")
    return json.loads(head), body


def split_mop(body: str) -> list[tuple[str, str]]:
    """Sections by heading; numbered steps, preconditions and rollback stay together within a section."""
    sections, title, buf = [], "Body", []
    for line in body.splitlines():
        if line.startswith("#"):
            if buf:
                sections.append((title, "\n".join(buf)))
            title, buf = line.lstrip("# ").strip(), []
        elif line.strip():
            buf.append(line)
    if buf:
        sections.append((title, "\n".join(buf)))
    return sections


def _children(text: str, size: int = 300) -> list[str]:
    out, cur = [], ""
    for line in text.splitlines():
        if cur and len(cur) + len(line) > size and not re.match(r"^\d+\.", line):
            out.append(cur)
            cur = ""
        cur = f"{cur}\n{line}".strip()
    return out + ([cur] if cur else [])


def ingest_dir(path: Path) -> int:
    n = 0
    for f in sorted(path.iterdir()):
        if f.suffix.lower() in (".txt", ".pdf"):
            n += ingest(*load(f))
    return n


def ingest(meta: dict, body: str) -> int:
    from .policy import CLASSIFICATION_LEVELS

    if not meta.get("doc_id") or meta.get("classification") not in CLASSIFICATION_LEVELS:
        raise ValueError("document identifier and known classification required")
    ocr = meta.get("ocr_confidence", 1.0 if meta.get("source_kind") != "scanned" else 0.7)
    n = 0
    with connect("platform") as c:
        old = c.execute("SELECT c.chunk_id, c.section_path, c.content, d.title FROM kb_chunk c "
                        "JOIN kb_document d ON d.doc_id=c.doc_id WHERE c.doc_id=? AND c.parent_id IS NOT NULL",
                        (meta["doc_id"],)).fetchall()
        for row in old:
            indexed = f"{row['title']} | {row['section_path']} | {row['content']}"
            c.execute("INSERT INTO kb_fts(kb_fts, rowid, content) VALUES ('delete', ?, ?)", (row["chunk_id"], indexed))
        c.execute("DELETE FROM kb_chunk WHERE doc_id=?", (meta["doc_id"],))
        c.execute("INSERT OR REPLACE INTO kb_document VALUES (?,?,?,?,?,?,?,?,?,?)",
                  tuple(meta.get(k) for k in ("doc_id", "family", "title", "revision", "effective_date", "vendor",
                                               "model", "firmware_range", "classification", "source_kind")))
        sections = split_mop(body)
        # one poisoned section makes the whole document untrusted, not just that section
        doc_poisoned = any(injection_score(t) >= QUARANTINE_AT for _, t in sections)
        for page, (section, text) in enumerate(sections, start=1):
            score = injection_score(text)
            parent = c.execute(
                "INSERT INTO kb_chunk(doc_id, section_path, content, classification, quarantined, injection_score,"
                " ocr_confidence, page) VALUES (?,?,?,?,?,?,?,?)",
                (meta["doc_id"], section, text, meta["classification"], int(doc_poisoned), score, ocr, page),
            ).lastrowid
            for child in _children(text):
                cs = injection_score(child)
                indexed = f"{meta.get('title', '')} | {section} | {child}"
                rid = c.execute(
                    "INSERT INTO kb_chunk(doc_id, parent_id, section_path, content, classification, quarantined,"
                    " injection_score, ocr_confidence, page, embedding) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (meta["doc_id"], parent, section, child, meta["classification"], int(doc_poisoned), cs, ocr, page,
                     json.dumps(llm.embed(indexed))),
                ).lastrowid
                c.execute("INSERT INTO kb_fts(rowid, content) VALUES (?, ?)", (rid, indexed))
                n += 1
    return n


def search(query: str, allowed_classes: set[str], device_model: str | None = None, k: int = 4) -> list[dict]:
    """Hybrid vector + FTS with RRF. ACL and quarantine filters applied *inside* SQL."""
    if not allowed_classes:
        return []
    ph = ",".join("?" * len(allowed_classes))
    filt = (f"c.quarantined = 0 AND c.parent_id IS NOT NULL AND c.classification IN ({ph})"
            " AND d.revision=(SELECT MAX(d2.revision) FROM kb_document d2 WHERE d2.family=d.family)")
    args: list = list(allowed_classes)
    if device_model:
        filt += " AND (d.model = ? OR d.model = '*')"
        args.append(device_model)
    stop = {"the", "and", "for", "how", "what", "can", "you", "with", "please", "does", "from", "this", "that"}
    terms = " OR ".join(f'"{t}"' for t in re.findall(r"[A-Za-z0-9]{3,}", query) if t.lower() not in stop) or '""'
    with connect("platform") as c:
        lex = [r[0] for r in c.execute(
            f"SELECT c.chunk_id FROM kb_fts JOIN kb_chunk c ON c.chunk_id = kb_fts.rowid JOIN kb_document d"
            f" ON d.doc_id = c.doc_id WHERE kb_fts MATCH ? AND {filt} ORDER BY bm25(kb_fts) LIMIT 40", [terms, *args])]
        if not lex:
            return []  # Hash embeddings alone cannot establish that an unrelated question has evidence.
        cands = c.execute(f"SELECT c.chunk_id, c.embedding FROM kb_chunk c JOIN kb_document d ON d.doc_id = c.doc_id"
                          f" WHERE {filt}", args).fetchall()
        qv = llm.embed(query)
        vec = [cid for cid, _ in sorted(((r[0], llm.cosine(qv, json.loads(r[1]))) for r in cands),
                                        key=lambda x: -x[1])[:40]]
        rrf: dict[int, float] = {}
        for ranked in (vec, lex):
            for i, cid in enumerate(ranked, start=1):
                rrf[cid] = rrf.get(cid, 0) + 1 / (60 + i)
        top = sorted(rrf, key=lambda x: -rrf[x])[: k * 2]
        rows = [dict(c.execute(
            "SELECT c.chunk_id, c.doc_id, c.section_path, c.page, c.ocr_confidence, p.content AS parent, d.family,"
            " d.revision, d.effective_date, d.title FROM kb_chunk c JOIN kb_chunk p ON p.chunk_id = c.parent_id"
            " JOIN kb_document d ON d.doc_id = c.doc_id WHERE c.chunk_id = ?", (cid,)).fetchone(), rrf=rrf[cid])
            for cid in top]
    # conflicts: prefer latest effective revision per family, surface superseded ones explicitly
    latest: dict[str, int] = {}
    for r in rows:
        latest[r["family"]] = max(latest.get(r["family"], 0), r["revision"])
    out, seen = [], set()
    for r in rows:
        if (r["doc_id"], r["section_path"]) in seen:
            continue
        seen.add((r["doc_id"], r["section_path"]))
        r["superseded"] = r["revision"] < latest[r["family"]]
        r["citation"] = f"{r['doc_id']}#{r['section_path']}/p{r['page']}"
        out.append(r)
    out.sort(key=lambda r: (r["superseded"], -r["rrf"]))
    return out[:k]
