# 🐤 Canary Scanner - Enterprise Secret Detection Platform (v4.0)

<div align="center">

[![Security](https://img.shields.io/badge/security-first-green.svg)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)]()
[![CI/CD](https://img.shields.io/badge/ci/cd-github_actions-green.svg)]()
[![Microservices](https://img.shields.io/badge/architecture-microservices-purple.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

**An intelligent, proactive, and scalable platform to prevent secrets from leaking into your codebase across your entire organization.**

[✨ Phase 4 Features](#-phase-4-enterprise-enhancements) • [🚀 Quick Start](#-quick-start) • [🏗️ Architecture](#️-architecture-phase-4) • [📚 Docs](#-documentation)

</div>

## ✨ Phase 4: Enterprise Enhancements

Canary Scanner has evolved beyond a simple CI/CD tool into a comprehensive security platform with:

* **🔬 Secret Validation:** Verifies if discovered keys (AWS, GitHub, etc.) are **active**, drastically reducing false positive noise and prioritizing real threats.
* **🧠 Contextual Awareness:** Intelligently understands code context (tests, docs, examples) to automatically filter or lower the severity of irrelevant findings.
* **⚡ Real-Time Scanning:** Uses GitHub App webhooks to detect secrets the **instant** they are committed to *any* repository in your organization, providing immediate alerts.
* **📊 Centralized Dashboard:** A web-based hub to view, manage, and analyze all findings, now enriched with validation status and context information.
* **🛡️ Microservice Architecture:** Decoupled components (Scanner, Dashboard, Validation Service) for enhanced scalability, resilience, and security.

## 🚀 Quick Start (Local Development via Docker Compose)

1.  **Clone:** `git clone <your-repo-url> && cd canary-scanner`
2.  **Configure:** Copy `.env.example` to `.env` and fill in required values (DB password, GitHub App details, Validation API Key).
3.  **Build & Run:** `docker-compose up --build -d`
4.  **Access:**
    * Dashboard: `http://localhost:8000` (or configured port)
    * Validation Service (Internal): `http://localhost:8001`
5.  **Run Manual Scan (Optional):**
    ```bash
    docker-compose run --rm scanner_cli . --validate
    ```

## 🏗️ Architecture (Phase 4)

Canary Scanner now operates as a microservices ecosystem:

```mermaid
graph TD
    subgraph GitHub
        A[Dev Push/PR] --> B{GitHub Actions}
        C[Dev Push (Real-time)] --> D[GitHub App Webhook]
    end

    subgraph "Canary CI/CD Scan"
        B -- Runs --> E[canary.py --validate]
        E -- Calls --> J[Validation API]
    end

    subgraph "Canary Platform (Local/Cloud)"
        F[🔬 Validation Service]
        G[📊 Dashboard API+Web+Webhook]
        H[POST /api/v1/scan]
        I[POST /api/v1/github-webhook]
        J[POST /api/v1/validate]
        K[🐘 PostgreSQL DB]
        L[🧠 Real-time Scanner Logic]
        M[💬 Slack Alerter]

        G --> H & I
        F --> J
        I -- Triggers --> L
        L -- Calls --> J; L -- Stores --> K; L -- Sends --> M
        G -- Stores --> K; F -- Updates --> K
    end

    E -- Reports --> H; J -- Returns --> E; D -- Sends --> I
