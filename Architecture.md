# Canary Scanner - Architecture Documentation 
======================================================

This document details the Phase 4 architecture of the Canary Scanner, which evolves into an enterprise-grade platform with microservices, secret validation, contextual awareness, and real-time scanning capabilities.

## 📋 Table of Contents

- [System Overview](#system-overview)
- [Architecture Principles](#architecture-principles)
- [Component Architecture (Phase 4)](#component-architecture-phase-4)
- [Data Flow (Phase 4)](#data-flow-phase-4)
- [Key Enhancements](#key-enhancements)
- [Security Design](#security-design)
- [Performance & Scalability](#performance--scalability)
- [Deployment Architecture](#deployment-architecture)

## 🎯 System Overview

Phase 4 transforms Canary Scanner into a proactive security intelligence platform. It focuses on accuracy (validation, context), speed (real-time), and coverage (organization-wide).

### Core Capabilities (Enhanced)
- **Context-Aware Detection**: Filters findings based on code context (test, docs, etc.).
- **Secret Validation**: Verifies the activity status of discovered secrets via a dedicated service.
- **Real-time Scanning**: Detects secrets instantly upon commit via GitHub App webhooks.
- **Centralized Dashboard**: Manages findings, tracks history, and provides insights, now including validation/context data.
- **Microservices Architecture**: Decouples validation and potentially real-time processing for scalability.

## 🏗️ Architecture Principles

(Keep principles like Separation of Concerns, Dependency Inversion, Immutable Data, Fail-Fast)

## 🔧 Component Architecture (Phase 4)

The system now consists of distinct, interacting components:

```mermaid
graph TD
    subgraph " "
    direction LR
    A("canary-scanner/")
    end

    subgraph "🚀 Scanner CLI & Core"
        direction TB
        B1("canary.py")
        B2("scanner/")
        B3("--- __init__.py")
        B4("--- core.py")
        B5("--- patterns.py")
        B6("--- context.py (New)")
        B7("--- filters.py (New)")
        B8("--- validators.py (New - Client)")
        B2 --> B3 & B4 & B5 & B6 & B7 & B8
    end

    subgraph "🔬 Validation Service (New Microservice)"
        direction TB
        C1("validation_service/")
        C2("--- __init__.py")
        C3("--- app.py (API)")
        C4("--- config.py")
        C5("--- requirements.txt")
        C6("--- validators/")
        C7("------ __init__.py")
        C8("------ base_validator.py")
        C9("------ aws_validator.py")
        C1 --> C2 & C3 & C4 & C5 & C6
        C6 --> C7 & C8 & C9
    end

    subgraph "📊 Dashboard & Real-time"
        direction TB
        D1("dashboard/")
        D2("--- app.py (API+Web+Webhook)")
        D3("--- models.py (DB Schema)")
        D4("--- config.py")
        D5("--- requirements.txt")
        D6("--- github_app.py (New)")
        D7("--- webhook_handler.py (New)")
        D8("--- realtime_scanner.py (New)")
        D9("--- migrations/")
        D10("------ versions/")
        D11("--------- 001_phase4.py (New)")
        D12("--- static/")
        D13("------ style.css & js")
        D14("--- templates/")
        D15("------ index/findings/scan_detail.html")
        D1 --> D2 & D3 & D4 & D5 & D6 & D7 & D8 & D9 & D12 & D14
        D9 --> D10 --> D11
    end

    subgraph "⚙️ Configuration"
        direction TB
        E1("config/")
        E2("--- context_rules.yml (New)")
        E3("--- validation_policies.yml (New)")
        E5("patterns.yml")
        E6(".env.example (New)")
        E1 --> E2 & E3
    end

    subgraph "🐳 Deployment & CI/CD"
        direction TB
        F1("Dockerfile (Multi-stage)")
        F2("docker-compose.yml (New)")
        F3(".dockerignore")
        F4(".github/workflows/secret-scan.yml")
    end

    A --> B1 & B2 & C1 & D1 & E1 & E5 & E6 & F1 & F2 & F3 & F4
