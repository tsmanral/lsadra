# LSADRA V4 Architecture

LSADRA is a multi-layered, AI-native Security Information and Event Management (SIEM) system designed for real-time anomaly detection, threat hunting, and explainable AI-driven security narratives. V4 introduces a premium, reactive frontend architecture and automated remediation playbooks.

## 1. System Overview

LSADRA processing pipeline follows a tiered approach:
1.  **Ingestion & Normalization:** High-throughput FastAPI layer for multi-source log ingestion.
2.  **Feature Extraction:** Conversion of raw telemetry into structured behavioral features using Pandas.
3.  **Heuristic & ML Detection:** Multi-layered detection stack using deterministic rules, statistical baselining, and ensemble ML.
4.  **Explainability & Narrative:** Generation of human-readable narratives from the per-layer detection scores and the rule engine's MITRE ATT&CK mapping. (The live pipeline does not compute SHAP values; `lsadra/explainability/shap_explainer.py` is not called by it.)
5.  **Reactive UI & Automation:** Modern React/TypeScript dashboard with interactive playbooks and real-time state synchronization.

---

## 2. Core Architecture Components

The application is structured into a Python backend (`lsadra/`) and a TypeScript frontend (`frontend/`).

### 2.1 Ingestion Layer (`lsadra/ingestion/`)
*   `api_ingestion.py`: FastAPI endpoints for ingestion and health stats.
*   `ingestion_manager.py`: Orchestrates multi-source parsers (Syslog, Windows, Network, Endpoint).

### 2.2 Feature Extraction (`lsadra/features/`)
*   `feature_extractor.py`: Transforms normalized events into temporal and behavioral feature vectors.

### 2.3 Detection & Analysis (`lsadra/detection/`)
*   `detection_orchestrator.py`: Manages the ML model lifecycle and coordinates the detection pipeline.
*   `rule_engine.py`: Deterministic threat correlation (Brute Force, Lateral Movement, etc.).
*   `incident_manager.py`: Aggregates anomalies into Security Incidents to reduce alert fatigue.

### 2.4 Storage & Database (`lsadra/storage/`)
*   `database.py`: Handles persistence using a thread-safe SQLite interface.
*   `migrations/`: Sequential SQL scripts for schema evolution (V4 includes `alerts_feedback` and `ingestion_stats`).

### 2.5 Reactive Frontend (`frontend/`)
Built with React 18, Vite, and Tailwind CSS, the new UI provides a premium SOC experience.
*   **Command Center**: Real-time dashboard with centralized KPI monitoring.
*   **Investigation Engine**: Interactive relationship graphs (Force-Directed) and behavior timelines.
*   **Playbook Automation**: Phased remediation workflows that execute commands on target hosts via the automation console.
*   **Global State Management**: Utilizes reactive hooks and local persistence for seamless page transitions.

---

## 3. Detailed Data Flow

1.  **Ingestion**: Agents send logs via HTTPS to the FastAPI server (Port 8000).
2.  **Normalization**: `IngestionManager` parses the raw strings into the `normalized_events` table.
3.  **Detection**: The background scheduler triggers the detection pipeline, evaluating features against ML models and the rule engine.
4.  **Incidient Creation**: Related anomalies are grouped into incidents. `NarrativeBuilder` generates the XAI narrative.
5.  **UI Visualization**: The React Frontend (Port 5173) fetches incident data via the REST API.
6.  **Remediation**: Analyst selects a playbook. The UI sends execution commands back to the backend or logs manual remediation steps.

---

## 4. Key Design Principles

1.  **Explainability First**: Every alert must be accompanied by a "Why" narrative built from the signals that raised it.
2.  **Premium Aesthetics**: Modern dark-mode interface with glassmorphic elements and high-density data visualizations.
3.  **Offline Autonomy**: Zero dependency on external LLMs or cloud APIs for core reasoning and narrative generation.
4.  **Actionable Intelligence**: Shift from passive alerting to active remediation via the Playbook system.
