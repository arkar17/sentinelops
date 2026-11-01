"""Imports every ORM model so Base.metadata is complete (Alembic env and schema tests)."""

from sentinelops.audit import models as audit_models
from sentinelops.catalog import models as catalog_models
from sentinelops.db.base import Base
from sentinelops.identity import models as identity_models
from sentinelops.incidents import models as incident_models
from sentinelops.measurements import models as measurement_models
from sentinelops.notifications import models as notification_models
from sentinelops.platform import models as platform_models
from sentinelops.scheduler import models as scheduler_models
from sentinelops.status_pages import models as status_page_models
from sentinelops.tenancy import models as tenancy_models

__all__ = [
    "Base",
    "audit_models",
    "catalog_models",
    "identity_models",
    "incident_models",
    "measurement_models",
    "notification_models",
    "platform_models",
    "scheduler_models",
    "status_page_models",
    "tenancy_models",
]
