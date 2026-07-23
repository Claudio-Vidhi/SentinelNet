from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from redundancy import service
from routers.deps import (
    assert_group_allowed,
    get_current_user,
    require_admin,
    user_group_scope,
)

router = APIRouter(tags=["Redundancy"])


class MemberWrite(BaseModel):
    device_ip: Optional[str] = None
    role: str = "unknown"
    serial: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    mgmt_ip: Optional[str] = None
    priority: Optional[int] = None
    state: str = "ready"
    details: dict[str, Any] = {}


class GroupWrite(BaseModel):
    id: Optional[int] = None
    group_name: str
    group_type: str
    name: str
    virtual_ip: Optional[str] = None
    logical_device_ip: Optional[str] = None
    health: str = "ok"
    members: list[MemberWrite] = []


@router.get("/api/redundancy/groups")
def list_redundancy_groups(current_user=Depends(get_current_user)):
    scope = user_group_scope(current_user)
    return {"results": service.list_groups(scope)}


@router.get("/api/redundancy/groups/{group_id}")
def get_redundancy_group(group_id: int, current_user=Depends(get_current_user)):
    g = service.get_group(group_id)
    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    scope = user_group_scope(current_user)
    if scope is not None and g.get("group_name") not in scope:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return g


@router.post("/api/redundancy/groups", status_code=status.HTTP_201_CREATED)
def create_redundancy_group(payload: GroupWrite, current_user=Depends(require_admin)):
    assert_group_allowed(current_user, payload.group_name)
    try:
        return service.save_manual_group(payload.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except service.ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.put("/api/redundancy/groups/{group_id}")
def update_redundancy_group(group_id: int, payload: GroupWrite, current_user=Depends(require_admin)):
    g = service.get_group(group_id)
    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    assert_group_allowed(current_user, g.get("group_name"))
    assert_group_allowed(current_user, payload.group_name)
    data = payload.model_dump()
    data["id"] = group_id
    try:
        return service.save_manual_group(data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except service.ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.delete("/api/redundancy/groups/{group_id}")
def delete_redundancy_group(group_id: int, current_user=Depends(require_admin)):
    g = service.get_group(group_id)
    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    assert_group_allowed(current_user, g.get("group_name"))
    service.delete_group(group_id)
    return {"status": "deleted", "id": group_id}
