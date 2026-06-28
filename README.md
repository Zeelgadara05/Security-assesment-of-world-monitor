# CyberAgent

**Autonomous AI Security Copilot**

CyberAgent is a production-grade security assessment platform designed for security researchers, bug bounty hunters, and DevSecOps teams. It orchestrates multiple reconnaissance and scanning utilities (Nmap, Nuclei, httpx, subfinder, assetfinder, dnsx, gau, WhatWeb) using an intelligent, multi-agent AI planner model.

---

## 🛠️ Architecture & Tech Stack

### Frontend
- **Framework**: React 19, Vite, TypeScript
- **Styling**: Tailwind CSS
- **Interactions**: Framer Motion
- **Topology Map**: React Flow (`@xyflow/react`)
- **Analytics Charts**: Recharts
- **Artifact Editor**: Monaco Editor (`@monaco-editor/react`)
- **Icons**: Lucide Icons

### Backend
- **Core Engine**: FastAPI (Python 3.8+)
- **ORM / Schema**: SQLAlchemy & Pydantic V2
- **Background Scans**: Celery Task runner with safe concurrent thread-pool executor fallback
- **SSE Streaming**: Live logs and scanner progress via Server Sent Events

---

## 🚀 Setup & Execution Guide

### Prerequisites
- Python 3.8+
- Node.js v18+ & NPM v10+

---

### Step 1: Run the Backend Service

1. Navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Install python dependencies:
   ```bash
   pip install fastapi uvicorn sqlalchemy pydantic
   ```
   *(Note: LiteLLM or celery packages are optional. The backend includes standalone fallback executors if dependencies are missing, ensuring high out-of-the-box portability).*

3. Run the FastAPI development server:
   ```bash
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

The backend API docs will be active at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### Step 2: Run the Frontend Dashboard

1. Navigate to the frontend folder:
   ```bash
   cd frontend
   ```
2. Build local assets and launch the development server:
   ```bash
   npm run dev
   ```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🔬 Security & Guardrails
- **Simulation Mode**: Enabled by default in configuration. This generates highly detailed, structured mock outputs of scanner tools without launching network probes. It ensures that reviewers can inspect the live dashboard, reports, SSE logs, and interactive graphs instantly without complex dependencies.
- **Strict Parameterization**: If production mode is toggled, all target commands are parsed into list-based sub-arguments via python's `subprocess` parser to secure against command injection vectors.
