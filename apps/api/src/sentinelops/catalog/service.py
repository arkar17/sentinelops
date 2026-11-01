"""Projects (FR-MON-001). Every query filters by the context's organization_id; an ID from another
organization is indistinguishable from a missing one (404)."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Project
from sentinelops.db.base import new_id
from sentinelops.errors import AppError
from sentinelops.tenancy.context import OrgContext


class ProjectNameTakenError(AppError):
    def __init__(self) -> None:
        super().__init__(409, "PROJECT_NAME_TAKEN", "An active project with this name exists")


def _audit(db: AsyncSession, ctx: OrgContext, action: str, project_id: uuid.UUID) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind="project",
        entity_id=project_id,
    )


async def list_projects(
    db: AsyncSession, ctx: OrgContext, *, include_archived: bool
) -> list[Project]:
    stmt = select(Project).where(Project.organization_id == ctx.organization_id)
    if not include_archived:
        stmt = stmt.where(Project.archived_at.is_(None))
    return list(await db.scalars(stmt.order_by(func.lower(Project.name))))


async def _get(db: AsyncSession, ctx: OrgContext, project_id: uuid.UUID) -> Project:
    project = await db.scalar(
        select(Project)
        .where(Project.organization_id == ctx.organization_id, Project.id == project_id)
        .with_for_update()
    )
    if project is None:
        raise AppError(404, "NOT_FOUND", "Project not found")
    return project


async def _commit_unique(db: AsyncSession) -> None:
    try:
        await db.flush()
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ProjectNameTakenError from exc


async def create_project(
    db: AsyncSession, ctx: OrgContext, *, name: str, description: str | None
) -> Project:
    now = clock.now()
    project = Project(
        id=new_id(),
        organization_id=ctx.organization_id,
        name=name,
        description=description,
        created_by=ctx.user_id,
        created_at=now,
        updated_at=now,
    )
    db.add(project)
    _audit(db, ctx, AuditAction.PROJECT_CREATED, project.id)  # id is generated client-side
    await _commit_unique(db)
    return project


async def update_project(
    db: AsyncSession,
    ctx: OrgContext,
    project_id: uuid.UUID,
    *,
    version: int,
    name: str | None,
    description: str | None,
) -> Project:
    project = await _get(db, ctx, project_id)
    if project.version != version:
        raise AppError(409, "VERSION_CONFLICT", "The project was changed; reload")
    if name is not None:
        project.name = name
    if description is not None:
        project.description = description
    project.version += 1
    _audit(db, ctx, AuditAction.PROJECT_UPDATED, project.id)
    await _commit_unique(db)
    return project


async def set_archived(
    db: AsyncSession, ctx: OrgContext, project_id: uuid.UUID, *, archived: bool
) -> Project:
    project = await _get(db, ctx, project_id)
    if (project.archived_at is not None) == archived:
        return project
    project.archived_at = clock.now() if archived else None
    project.version += 1
    action = AuditAction.PROJECT_ARCHIVED if archived else AuditAction.PROJECT_UNARCHIVED
    _audit(db, ctx, action, project.id)
    await _commit_unique(db)
    return project
