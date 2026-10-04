"""Which project a Skywalker call is about.

users.yaml gives each person a `projects` list (exact ids, or prefixes ending in
`*`). What it means depends on the role:

- `read`: the only projects the person may ask about. A call naming any other
  project is refused before Google is asked, even if the person's own Google
  account could see it. No list means no project.
- `staff` / `admin`: any project their own Google account can see. The list only
  gives the default.

Each person also has a *focus*, kept in the sealed store and shared by all their
clients (Claude, Hermes, Gemini Enterprise): the project a call is about when it
names none. It starts as the first exact id in their list. Staff and admins may
set it to any project, or to `all`, which makes `skywalker_overview` answer for
every project (the fleet view). A read user may move it between their own
projects.
"""

from __future__ import annotations

from typing import Any, Protocol

from auth import Identity
from mcp.server.fastmcp.exceptions import ToolError
from users import default_project, project_allowed, role_at_least

ALL = "all"
KIND = "focus"


class Store(Protocol):
    def get(self, kind: str, key: str) -> dict[str, Any] | None: ...
    def put(self, kind: str, key: str, value: dict[str, Any]) -> None: ...
    def delete(self, kind: str, key: str) -> bool: ...


def is_staff(ident: Identity) -> bool:
    return role_at_least(ident.role, "staff")


def stored_focus(store: Store | None, ident: Identity) -> str:
    """The person's saved focus, if it is still one they may use."""
    if store is None:
        return ""
    rec = store.get(KIND, ident.email) or {}
    value = str(rec.get("project") or "")
    if not value:
        return ""
    if is_staff(ident):
        return value
    # A read user's saved focus stops counting once the project leaves their list.
    return value if value != ALL and project_allowed(ident.projects, value) else ""


def focus(store: Store | None, ident: Identity) -> str:
    """The project (or `all`) a call is about when it names none; "" if none."""
    return stored_focus(store, ident) or default_project(ident.projects)


def set_focus(store: Store, ident: Identity, value: str) -> None:
    store.put(KIND, ident.email, {"project": value})


def clear_focus(store: Store, ident: Identity) -> None:
    store.delete(KIND, ident.email)


def _yours(ident: Identity) -> str:
    return ", ".join(ident.projects) if ident.projects else "none"


def check_allowed(ident: Identity, project: str) -> None:
    """Refuse a read user's project outside their list (staff: Google decides)."""
    if is_staff(ident):
        return
    if project == ALL or not project_allowed(ident.projects, project):
        raise ToolError(
            f"{project} is not one of your Skywalker projects (yours: "
            f"{_yours(ident)}). Ask Research Computing to add it."
        )


def resolve(
    ident: Identity, store: Store | None, project_id: str, allow_all: bool = False
) -> str:
    """The project id this call is about, or `all` when allow_all and focused so.

    Raises ToolError (a normal MCP error) when there is no project, or when a read
    user names a project outside their list.
    """
    pid = (project_id or "").strip().lower()
    if not pid:
        pid = focus(store, ident)
    if not pid:
        if is_staff(ident):
            raise ToolError(
                "which project? Pass project_id, or set a default with skywalker_focus."
            )
        raise ToolError(
            "no Google Cloud project is assigned to you on Skywalker yet; ask "
            "Research Computing to add yours."
        )
    if pid == ALL:
        if not is_staff(ident):
            raise ToolError("'all' is for staff; you can ask about your own projects.")
        if not allow_all:
            raise ToolError(
                "your focus is 'all' (every project). This tool looks at one "
                "project: pass project_id, or use skywalker_overview / "
                "skywalker_fleet for the whole fleet."
            )
        return ALL
    check_allowed(ident, pid)
    return pid
