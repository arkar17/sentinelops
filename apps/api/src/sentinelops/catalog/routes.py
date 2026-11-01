"""Project routes under /api/orgs/{org_id}/projects. Each route declares one permission action."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from sentinelops.catalog import service
from sentinelops.catalog.models import Project
from sentinelops.db.session import DbSession
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}/projects", tags=["projects"])

Name = Annotated[str, Field(min_length=1, max_length=120, pattern=r"\S")]
Description = Annotated[str, Field(max_length=1000)]


class ProjectCreate(BaseModel):
    name: Name
    description: Description | None = None


class ProjectUpdate(BaseModel):
    version: int
    name: Name | None = None
    description: Description | None = None


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    archived_at: datetime | None
    created_at: datetime
    version: int


def _out(project: Project) -> ProjectOut:
    return ProjectOut.model_validate(project, from_attributes=True)


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    ctx: Annotated[OrgContext, Depends(OrgPermission("PRJ.view"))],
    db: DbSession,
    include_archived: bool = False,
) -> list[ProjectOut]:
    return [
        _out(p) for p in await service.list_projects(db, ctx, include_archived=include_archived)
    ]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    ctx: Annotated[OrgContext, Depends(OrgPermission("PRJ.create"))],
    db: DbSession,
) -> ProjectOut:
    project = await service.create_project(
        db, ctx, name=body.name.strip(), description=body.description
    )
    return _out(project)


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    ctx: Annotated[OrgContext, Depends(OrgPermission("PRJ.update"))],
    db: DbSession,
) -> ProjectOut:
    project = await service.update_project(
        db,
        ctx,
        project_id,
        version=body.version,
        name=body.name.strip() if body.name else None,
        description=body.description,
    )
    return _out(project)


@router.post("/{project_id}/archive", response_model=ProjectOut)
async def archive_project(
    project_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(OrgPermission("PRJ.archive"))],
    db: DbSession,
) -> ProjectOut:
    return _out(await service.set_archived(db, ctx, project_id, archived=True))


@router.post("/{project_id}/unarchive", response_model=ProjectOut)
async def unarchive_project(
    project_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(OrgPermission("PRJ.archive"))],
    db: DbSession,
) -> ProjectOut:
    return _out(await service.set_archived(db, ctx, project_id, archived=False))
