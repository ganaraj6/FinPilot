# FinPilot

AI-powered personal finance platform focused on improving financial habits rather
than simply tracking wealth.

## Architecture

- **Backend**: FastAPI, SQLAlchemy, Alembic, PostgreSQL (Neon), Repository + Service layers,
  JWT authentication, bcrypt, APScheduler.
- **Frontend**: React, TypeScript, Vite, TailwindCSS, Zustand.
- **Deployment**: Frontend on Vercel, Backend on Render, Database on Neon, AI via Groq,
  storage via Cloudinary.

> This is the initial project skeleton only. Business logic, APIs, and authentication are
> intentionally not implemented yet. Module packages contain placeholders only.

## Project structure

```
backend/
  app/
    core/            # Cross-cutting infrastructure (security, middleware)
    config/          # Typed settings loaded from environment variables
    database/        # Engine, session factory, declarative base
    models/          # ORM model aggregator for Alembic autogenerate
    repositories/    # Shared repository base primitives
    services/        # Shared service base primitives
    routers/         # Aggregated module routers
    modules/         # Feature modules (auth, dashboard, expenses, money, goals,
                     # budgets, reports, notifications, ai, health_score, settings)
  alembic/           # Alembic migration environment and versions
  alembic.ini
  requirements.txt
  requirements-dev.txt
  pyproject.toml     # Ruff lint/format configuration
frontend/
  src/
    components/      # Reusable UI components (placeholder)
    pages/           # Page-level components
    hooks/           # Custom React hooks (placeholder)
    store/           # Zustand stores (placeholder)
    services/        # API client services (placeholder)
    types/           # Shared TypeScript types (placeholder)
docs/                # Project documentation (placeholder)
database/            # Database scripts, seeds, and SQL assets (placeholder)
assets/              # Shared static assets (placeholder)
```

Each backend module contains placeholder files: `router.py`, `service.py`,
`repository.py`, `schemas.py`, `models.py`, and `__init__.py`.

## Prerequisites

- Python 3.11+
- Node.js 20+

## Backend setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate          # macOS / Linux

pip install -r requirements.txt
pip install -r requirements-dev.txt

copy .env.example .env             # Windows
cp .env.example .env               # macOS / Linux
# Edit .env and set DATABASE_URL to your Neon PostgreSQL connection string.
```

Run the development server:

```bash
uvicorn app.main:app --reload
```

The API documentation is available at <http://127.0.0.1:8000/docs>.

### Database migrations (Alembic)

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Migrations read `DATABASE_URL` from your environment/`.env` via
`app/config/settings.py`.

### Linting and formatting

```bash
ruff check .
ruff format .
```

## Frontend setup

```bash
cd frontend
npm install
copy .env.example .env             # Windows
cp .env.example .env               # macOS / Linux
```

Run the development server:

```bash
npm run dev
```

### Linting and formatting

```bash
npm run lint
npm run format
```

## Environment variables

| Variable        | Where     | Description                                        |
| --------------- | --------- | -------------------------------------------------- |
| `DATABASE_URL`  | backend   | PostgreSQL connection string (Neon)                |
| `APP_NAME`      | backend   | Application name                                   |
| `ENVIRONMENT`   | backend   | Runtime environment (`development` / `production`) |
| `DEBUG`         | backend   | Enable debug mode                                  |
| `VITE_API_URL`  | frontend  | Base URL of the backend API                        |

## Deployment notes

- Frontend on Vercel: set `VITE_API_URL` to the deployed Render backend URL.
- Backend on Render: set `DATABASE_URL` to the Neon connection string.
