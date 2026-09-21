"""Cross-scan finding tracking (Phase 7).

Same-fingerprint findings are linked across scans so operators can see whether a
finding is new, recurring, reintroduced or stable.  ``update_cross_scan`` stamps
``first_scan_id`` / ``last_scan_id`` / ``occurrence_count`` on every scan of the
current one; ``compare`` produces a deterministic added/removed/retained/
reintroduced diff between two scans.
"""
from __future__ import annotations

from sqlalchemy import func, or_

from database.models import Vulnerability


def fingerprint_of(f) -> str:
    return (f.fingerprint or f.dedup_key or
            f"{f.rule_id or 'legacy'}|{(f.target or '')}|{(f.title or '').strip()}")


def _key_match(f) -> dict:
    key = f.fingerprint or f.dedup_key
    if key:
        return {"a": f.fingerprint or key, "b": f.dedup_key or key}
    literal = fingerprint_of(f)
    return {"a": literal, "b": literal}


def update_cross_scan(db, scan) -> dict:
    """Stamp first/last scan and occurrence count for this scan's findings."""
    findings = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .all()
    )
    updated = 0
    for f in findings:
        key = fingerprint_of(f)
        if not key:
            continue
        same = (
            db.query(Vulnerability)
            .filter(or_(
                Vulnerability.fingerprint == key,
                Vulnerability.dedup_key == key,
            ))
            .all()
        )
        count = len(same)
        earliest = min((g.scan_id for g in same if g.scan_id is not None), default=None)
        f.first_scan_id = earliest or scan.id
        f.last_scan_id = scan.id
        f.occurrence_count = count
        updated += 1
    db.flush()
    return {"updated": updated, "findings": len(findings)}


def _scan_keys(db, scan_id: int) -> dict[str, int]:
    """fingerprint -> row id for every open finding of one scan."""
    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    return {fingerprint_of(f): f.id for f in findings if fingerprint_of(f)}


def _scan_key_ids(db, scan_id: int) -> set[str]:
    return set(_scan_keys(db, scan_id))


def compare(db, scan_a_id: int, scan_b_id: int) -> dict:
    """Diff two scans of the same target.

    ``added`` keys exist only in scan B; ``removed`` only in scan A;
    ``retained`` in both; ``reintroduced`` were seen before A, then absent in A,
    and are present again in B.

    Reintroduction history is scoped to the target being compared: fingerprints
    from unrelated targets are never treated as historical evidence for this
    target, so a fingerprint that only ever appeared on another host is
    ``added`` here, not ``reintroduced``.  Comparing scans of different targets
    returns raw added/removed/retained with empty reintroduction (the semantics
    are undefined across targets); the API layer flags that with a note.
    """
    from sqlalchemy import and_

    from database.models import Scan

    if scan_a_id == scan_b_id:
        keys = _scan_key_ids(db, scan_a_id)
        return {
            "scan_a": scan_a_id, "scan_b": scan_b_id,
            "added": [], "removed": [], "retained": sorted(keys),
            "reintroduced": [], "same_target": True,
        }

    scan_a = db.query(Scan).filter(Scan.id == scan_a_id).first()
    scan_b = db.query(Scan).filter(Scan.id == scan_b_id).first()
    same_target = bool(
        scan_a is not None and scan_b is not None
        and (scan_a.target or "").strip() == (scan_b.target or "").strip()
    )

    a_keys = _scan_key_ids(db, scan_a_id)
    b_keys = _scan_key_ids(db, scan_b_id)

    reintroduced: set[str] = set()
    if same_target:
        older = (
            db.query(Vulnerability.scan_id)
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .filter(
                Vulnerability.scan_id != scan_a_id,
                Vulnerability.scan_id != scan_b_id,
                and_(
                    Scan.target.is_not(None),
                    Scan.target == (scan_a.target or "").strip(),
                ),
            )
            .all()
        )
        older_scans = sorted({sid for (sid,) in older})
        historically_present: set[str] = set()
        for sid in older_scans:
            historically_present |= _scan_key_ids(db, sid)
        reintroduced = {
            k for k in b_keys
            if k in historically_present and k not in a_keys
        }

    added = sorted(k for k in b_keys if k not in a_keys and k not in reintroduced)
    removed = sorted(a_keys - b_keys)
    retained = sorted(a_keys & b_keys)
    return {
        "scan_a": scan_a_id,
        "scan_b": scan_b_id,
        "added": added,
        "removed": removed,
        "retained": retained,
        "reintroduced": sorted(reintroduced),
        "same_target": same_target,
    }


__all__ = ["fingerprint_of", "update_cross_scan", "compare"]