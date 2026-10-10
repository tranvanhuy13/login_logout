"""
authorization.py - roles and capabilities, exactly as in the permission table:

    Capability                                              Viewer  Operator  Admin
    Live streams and camera status                            yes     yes      yes
    Real-time alerts, history, stats, snapshots               yes     yes      yes
    Mute or unmute the alarm sound (own browser only)         yes     yes      yes
    Acknowledge alerts / mark false alarm                     -       yes      yes
    Turn a camera on/off                                      -       yes      yes
    Analyze uploaded video                                    -       yes      yes
    Send a test notification                                  -       yes      yes
    Add, edit or delete cameras                               -       -        yes
    Change AI settings (threshold, persistence, cooldown)     -       -        yes
    Set Zalo/Telegram tokens, recipients, public URL          -       -        yes
    Manage users and roles                                    -       -        yes
    View the audit log                                        -       -        yes

3 roles, 12 capabilities - nothing more, nothing less.
"""
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from authentication import audit, get_current_user, get_db


# --------------------------------------------------------------------------- roles
class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


# --------------------------------------------------------------------------- capabilities
class Capability(str, Enum):
    VIEW_STREAMS = "view_streams"                       # live streams and camera status
    VIEW_ALERTS = "view_alerts"                         # real-time alerts, history, stats, snapshots
    MUTE_ALARM = "mute_alarm"                           # own browser only
    ACK_ALERTS = "ack_alerts"                           # acknowledge alerts / mark false alarm
    TOGGLE_CAMERA = "toggle_camera"                     # turn a camera on/off
    ANALYZE_VIDEO = "analyze_video"                     # analyze uploaded video
    SEND_TEST_NOTIFICATION = "send_test_notification"
    MANAGE_CAMERAS = "manage_cameras"                   # add, edit or delete cameras
    CHANGE_AI_SETTINGS = "change_ai_settings"           # threshold, persistence, cooldown
    SET_NOTIFICATION_SETTINGS = "set_notification_settings"  # Zalo/Telegram tokens, recipients, public URL
    MANAGE_USERS = "manage_users"                       # users and roles
    VIEW_AUDIT_LOG = "view_audit_log"


_VIEWER = frozenset({
    Capability.VIEW_STREAMS,
    Capability.VIEW_ALERTS,
    Capability.MUTE_ALARM,
})

_OPERATOR = _VIEWER | frozenset({
    Capability.ACK_ALERTS,
    Capability.TOGGLE_CAMERA,
    Capability.ANALYZE_VIDEO,
    Capability.SEND_TEST_NOTIFICATION,
})

_ADMIN = frozenset(Capability)  # everything

ROLE_CAPABILITIES = {
    Role.VIEWER: _VIEWER,
    Role.OPERATOR: _OPERATOR,
    Role.ADMIN: _ADMIN,
}


def capabilities_of(role) -> frozenset:
    try:
        return ROLE_CAPABILITIES[Role(role)]
    except (ValueError, KeyError):
        return frozenset()  # unknown role -> no rights


def has_capability(role, capability: Capability) -> bool:
    return capability in capabilities_of(role)


# --------------------------------------------------------------------------- guards
def require_capability(capability: Capability):
    """Dependency factory:  user = Depends(require_capability(Capability.TOGGLE_CAMERA))"""
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        if not has_capability(user["role"], capability):
            audit("permission_denied", user["username"], capability.value)
            raise HTTPException(status_code=403, detail="Your role is not allowed to do this.")
        return user
    return dependency


# POST /settings carries one key at a time, so each key maps to the capability that protects it.
SETTING_CAPABILITY = {
    "ai_confidence_threshold": Capability.CHANGE_AI_SETTINGS,
    "ai_persistence_frames": Capability.CHANGE_AI_SETTINGS,
    "ai_cooldown_seconds": Capability.CHANGE_AI_SETTINGS,
    "zalo_enabled": Capability.SET_NOTIFICATION_SETTINGS,
    "zalo_bot_token": Capability.SET_NOTIFICATION_SETTINGS,
    "zalo_chat_id": Capability.SET_NOTIFICATION_SETTINGS,
    "public_base_url": Capability.SET_NOTIFICATION_SETTINGS,
    "telegram_enabled": Capability.SET_NOTIFICATION_SETTINGS,
    "telegram_bot_token": Capability.SET_NOTIFICATION_SETTINGS,
    "telegram_chat_id": Capability.SET_NOTIFICATION_SETTINGS,
    "alarm_sound_enabled": Capability.MUTE_ALARM,
}


def ensure_can_change_setting(user: dict, key: str):
    """Call inside POST /settings. Unknown keys are rejected."""
    capability = SETTING_CAPABILITY.get(key)
    if capability is None:
        raise HTTPException(status_code=400, detail=f"Unknown setting '{key}'.")
    if not has_capability(user["role"], capability):
        audit("permission_denied", user["username"], f"setting:{key}")
        raise HTTPException(status_code=403, detail="Your role is not allowed to change this setting.")


# --------------------------------------------------------------------------- routes
router = APIRouter(tags=["authorization"])


@router.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    """Current user + what they may do (the frontend uses this to hide/disable buttons)."""
    return {
        "user": user,
        "capabilities": sorted(c.value for c in capabilities_of(user["role"])),
    }


class RoleBody(BaseModel):
    role: str


@router.get("/admin/users")
def list_users(user: dict = Depends(require_capability(Capability.MANAGE_USERS))):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, email, role, status, created_at FROM users ORDER BY id").fetchall()
    return {"users": [dict(r) for r in rows]}


@router.put("/admin/users/{user_id}/role")
def set_user_role(user_id: int, body: RoleBody,
                  admin: dict = Depends(require_capability(Capability.MANAGE_USERS))):
    try:
        new_role = Role(body.role)
    except ValueError:
        raise HTTPException(status_code=422,
                            detail=f"Role must be one of: {', '.join(r.value for r in Role)}.")
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="You cannot change your own role.")

    with get_db() as conn:
        target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="User not found.")
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role.value, user_id))

    audit("role_changed", admin["username"], f"{target['username']} -> {new_role.value}")
    return {"status": "ok", "message": f"{target['username']} is now {new_role.value}"}


@router.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_capability(Capability.MANAGE_USERS))):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    with get_db() as conn:
        target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="User not found.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))  # sessions/OTP cascade

    audit("user_deleted", admin["username"], target["username"])
    return {"status": "ok", "message": "User deleted"}


@router.get("/admin/audit-log")
def get_audit_log(limit: int = 100, offset: int = 0,
                  user: dict = Depends(require_capability(Capability.VIEW_AUDIT_LOG))):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, username, action, detail, ip FROM audit_log "
            "ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    return {"entries": [dict(r) for r in rows]}