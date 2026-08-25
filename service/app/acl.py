"""Matter ACL helpers (PR 16).

One row per (matter, user, perm). The single-tenant local profile runs as
the fixed OPERATOR subject, which gets OWNER_PERMS on matter creation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import KNOWN_PERMS, OWNER_PERMS, MatterAcl

OPERATOR = "operator"


def bootstrap_operator(s: Session, matter_id: str, user_id: str = OPERATOR) -> None:
    for perm in OWNER_PERMS:
        s.add(MatterAcl(matter_id=matter_id, user_id=user_id, perm=perm))
    s.commit()


def has_perm(s: Session, matter_id: str, user_id: str, perm: str) -> bool:
    return (
        s.query(MatterAcl).filter_by(matter_id=matter_id, user_id=user_id, perm=perm).first()
        is not None
    )


def grant(s: Session, matter_id: str, user_id: str, perm: str) -> None:
    if perm not in KNOWN_PERMS:
        raise ValueError(f"unknown permission: {perm}")
    if not has_perm(s, matter_id, user_id, perm):
        s.add(MatterAcl(matter_id=matter_id, user_id=user_id, perm=perm))
        s.commit()


def revoke(s: Session, matter_id: str, user_id: str, perm: str) -> None:
    """Delete one (matter, user, perm) grant.

    Refuses to remove the matter's *last* admin grant, full stop -- no
    confirmation flag overrides this (see app.main.delete_acl for that;
    it's a separate, narrower self-lockout guard). Granting admin itself
    requires the admin perm (app.main.put_acl's _require call), so a
    matter that ever reaches zero admin grants can never have one added
    back through the API again -- permanently locking out ACL management
    on that matter. Enforced here, at the function callers actually use,
    rather than only in the one route that calls it today.
    """
    if perm == "admin" and has_perm(s, matter_id, user_id, "admin"):
        admin_count = s.query(MatterAcl).filter_by(matter_id=matter_id, perm="admin").count()
        if admin_count <= 1:
            raise ValueError("cannot revoke the last admin grant on this matter")
    s.query(MatterAcl).filter_by(matter_id=matter_id, user_id=user_id, perm=perm).delete()
    s.commit()


def perms_of(s: Session, matter_id: str, user_id: str) -> list[str]:
    rows = s.query(MatterAcl).filter_by(matter_id=matter_id, user_id=user_id).all()
    return sorted(r.perm for r in rows)


def list_grants(s: Session, matter_id: str) -> list[dict]:
    """Every (user_id, perms) pair currently granted on a matter, for the
    Access panel -- one row per user_id, perms sorted, users sorted so the
    list renders in a stable order across requests."""
    rows = s.query(MatterAcl).filter_by(matter_id=matter_id).all()
    by_user: dict[str, list[str]] = {}
    for r in rows:
        by_user.setdefault(r.user_id, []).append(r.perm)
    return [
        {"user_id": user_id, "perms": sorted(perms)}
        for user_id, perms in sorted(by_user.items())
    ]
