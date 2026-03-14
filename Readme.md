# Lumina FPM (Firewall Policy Manager)

A proactive, centralized platform for acquiring, normalizing, and analyzing multi-vendor firewall policies (Palo Alto & Fortinet) with an integrated Dark Web Threat Intelligence engine.

## 🏗️ Architecture Stack
* **Backend:** FastAPI (Python 3.11), SQLAlchemy, Celery
* **Frontend:** React (Vite), Cytoscape.js
* **Database:** PostgreSQL 16
* **Infrastructure:** Docker & Docker Compose

## 🚀 Quick Start Guide (For Developers)

### Prerequisites
1. You must have [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. Do **not** install PostgreSQL or Python locally. Everything runs in containers.
3. Ask the Team Lead (@Kandeel) for the `.env` file and place it in the root directory.

### Booting the Environment
Open your terminal in the root folder and run:
`docker-compose up --build -d`

* The API will be live at: `http://localhost:8000`
* The Frontend will be live at: `http://localhost:5173`

### Stopping the Environment
`docker-compose down`

## 🛑 Contribution Rules
1. **Never push to `main`.** Create a feature branch: `git checkout -b feature/your-task-name`
2. **Pull Request Mandatory:** You must fill out the GitHub PR template and link your Notion Engineering Log before requesting a review.
