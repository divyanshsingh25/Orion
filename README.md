# Orion

An AI-powered web application security assessment platform for automated vulnerability detection, intelligent analysis, and comprehensive security reporting.

---

## Quick Start Guide

### 1. Prerequisites
- **Python 3.10+**
- **Node.js 18+** & npm
- *(Optional)* **Redis** & **PostgreSQL** (SQLite supported by default for local development)

---

### 2. Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/divyanshsingh25/Orion.git
   cd Orion
   ```

2. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv .venv
   
   # Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1
   # Windows (CMD):
   .\.venv\Scripts\activate.bat
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright browsers (for crawler & DOM scanning):**
   ```bash
   playwright install chromium
   ```

5. **Configure environment variables:**
   ```bash
   # Copy sample environment file
   copy backend\.env.example backend\.env   # Windows
   # cp backend/.env.example backend/.env   # Linux/macOS
   ```
   *Edit `backend/.env` to configure your API keys (e.g. OpenAI/LLM keys, secret keys, or database URLs).*

6. **Start the backend server:**
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload --port 8123
   ```
   API Docs will be available at: `http://localhost:8123/docs`

---

### 3. Frontend Setup

1. **Navigate to the frontend folder:**
   ```bash
   cd frontend
   ```

2. **Install Node dependencies:**
   ```bash
   npm install
   ```

3. **Run the frontend development server:**
   ```bash
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

---

## License
MIT License. See [LICENSE](LICENSE) for details.
