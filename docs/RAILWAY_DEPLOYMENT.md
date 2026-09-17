# Deploying Orion Backend to Railway

This guide walks you through deploying the Orion FastAPI Backend and PostgreSQL database on [Railway](https://railway.app/).

---

## 1. Quick Start / Recommended Setup

### Step 1: Add a PostgreSQL Database on Railway
1. Open your Railway Project dashboard.
2. Click **+ New** -> **Database** -> **Add PostgreSQL**.
3. Railway will provision a dedicated PostgreSQL 16 instance.
4. Railway will automatically expose the `DATABASE_URL` variable.

---

### Step 2: Deploy the Orion Backend Service
1. In the same project, click **+ New** -> **GitHub Repo** -> select your `Orion` repository.
2. Go to the newly created service's **Settings** tab.
3. Configure the **Build & Deploy** settings:

| Setting | Value | Notes |
| :--- | :--- | :--- |
| **Root Directory** | `backend` | Sets build & runtime directory to `backend/` |
| **Custom Start Command** | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` | Starts FastAPI on Railway's assigned `$PORT` |

---

### Step 3: Configure Environment Variables
Under the service **Variables** tab, add the following:

#### Required Variables
| Variable | Value / Description | Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | Connect to your Railway PostgreSQL service | `${{Postgres.DATABASE_URL}}` *(Reference variable)* |
| `SECRET_KEY` | 32+ character random string for JWT signing | `openssl rand -hex 32` |
| `FRONTEND_URL` | URL of your deployed frontend (for CORS & auth redirects) | `https://orion-frontend.vercel.app` |
| `ORION_CORS_ORIGINS` | Comma-separated list of allowed frontend origins | `https://orion-frontend.vercel.app,http://localhost:5173` |

#### Optional / AI Variables
| Variable | Value / Description | Default |
| :--- | :--- | :--- |
| `ORION_LLM_API_KEY` | OpenRouter / OpenAI API key for AI Verification & Chat Copilot | `None` (graceful fallback) |
| `ORION_LLM_BASE_URL` | Base URL for LLM provider API | `https://openrouter.ai/api/v1` |
| `ORION_LLM_MODEL` | AI Model identifier | `openai/gpt-4o-mini` |
| `ORION_ALLOW_PRIVATE_TARGETS` | Allow scanning local/private RFC1918 IPs | `false` |
| `ORION_SCAN_MAX_DURATION_SECONDS`| Max duration limit for full scans | `900.0` (15 mins) |

---

## 2. Automatic URL & Database Schema Initialization
- **Automatic `DATABASE_URL` normalization**: Railway supplies `postgresql://...` or `postgres://...`. Orion automatically normalizes this to `postgresql+asyncpg://...` upon boot.
- **Automatic Schema Migration**: When `ORION_ENABLE_AUTO_SCHEMA=true` (the default), Orion runs `init_database()` on startup, automatically creating all necessary tables in PostgreSQL.

---

## 3. Verifying the Deployment
Once deployed, check the Railway **Deployments Logs**:
1. You should see:
   ```text
   INFO:     Started server process [...]
   INFO:     Waiting for application startup.
   INFO:     Application startup complete.
   INFO:     Uvicorn running on http://0.0.0.0:xxxx (Press CTRL+C to quit)
   ```
2. Test the health endpoint by visiting:
   ```
   https://<your-railway-backend-url>/health
   ```
   Expected response:
   ```json
   {"status": "ok", "service": "ORION"}
   ```

---

## 4. Troubleshooting

- **502 Bad Gateway / Application crashed**: Check that `DATABASE_URL` is set to the PostgreSQL service variable `${{Postgres.DATABASE_URL}}`.
- **WebSocket connection failed**: Ensure your frontend connects to `wss://<your-railway-url>/api/v1/scans/ws/{scan_id}?token=...`.
- **CORS error**: Add your frontend domain to `ORION_CORS_ORIGINS` in Railway environment variables.
