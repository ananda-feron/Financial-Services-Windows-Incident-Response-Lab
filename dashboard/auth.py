"""Demonstration RBAC policy; this is not a production identity system."""

from __future__ import annotations

from functools import wraps

from flask import abort, g, request

ROLES = ("VIEWER", "ANALYST", "INCIDENT_RESPONDER", "ADMIN")
PERMISSIONS = {
    "VIEWER": {"view"},
    "ANALYST": {"view", "add_note"},
    "INCIDENT_RESPONDER": {"view", "add_note", "respond"},
    "ADMIN": {"view", "add_note", "respond", "manage_rules"},
}


def load_role() -> None:
    role = request.headers.get("X-Lab-Role", request.args.get("role", "VIEWER")).upper()
    g.role = role if role in ROLES else "VIEWER"


def require(permission: str):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if permission not in PERMISSIONS[g.role]:
                abort(403)
            return function(*args, **kwargs)
        return wrapped
    return decorator
