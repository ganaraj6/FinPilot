"""ORM model aggregator.

Importing this package registers every module's models on Base.metadata so
Alembic autogenerate and the application can discover all ORM tables.
"""

from app.modules.ai import models as ai_models  # noqa: F401
from app.modules.auth import models as auth_models  # noqa: F401
from app.modules.budgets import models as budgets_models  # noqa: F401
from app.modules.dashboard import models as dashboard_models  # noqa: F401
from app.modules.expenses import models as expenses_models  # noqa: F401
from app.modules.goals import models as goals_models  # noqa: F401
from app.modules.health_score import models as health_score_models  # noqa: F401
from app.modules.money import models as money_models  # noqa: F401
from app.modules.notifications import models as notifications_models  # noqa: F401
from app.modules.reports import models as reports_models  # noqa: F401
from app.modules.settings import models as settings_models  # noqa: F401
