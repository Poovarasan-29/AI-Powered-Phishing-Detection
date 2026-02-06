# AI-Based Phishing Detection System

## Project Overview
This project aims to design and implement a dynamic, AI-driven phishing detection system for Chrome browser URLs. It determines malicious intent by analyzing URL structure, semantic indicators, webpage content similarity, and behavioral actions.

**Core Principle:** This system **DOES NOT** rely on static rules, hardcoded trusted domains, or blacklist-based checks. It uses a probabilistic, multi-layered approach to detect zero-day phishing attacks.

## Architecture: Multi-Layered Detection Pipeline

The system employs a 5-stage analysis pipeline:

1.  **Stage 1: URL-Level Risk Assessment**
    *   Real-time analysis of lexical, structural, and statistical features.
    *   LightGBM model for initial risk scoring.
    *   **No hardcoded trusted domains.**

2.  **Stage 2: Semantic and Intent Analysis**
    *   Transformer-based embeddings to detect intent and impersonation.
    *   Typosquatting and homoglyph detection using learned representations.

3.  **Stage 3: Webpage Content & Visual Similarity**
    *   DOM structure and visual layout analysis.
    *   Content fingerprinting to detect template plagiarism.

4.  **Stage 4: Behavioral Inspection**
    *   Analysis of form submissions, redirects, and background network activity.
    *   Contextual evaluation of authentication forms.

5.  **Stage 5: Risk Aggregation & Explainability**
    *   Probabilistic scoring combining all signals.
    *   User-friendly explanations for *why* a site was flagged.

## Technology Stack
- **Backend:** Python (Flask/FastAPI) for model serving and heavy analysis.
- **Frontend/Extension:** JavaScript (Chrome Extension API) for interception and lightweight analysis.
- **ML Models:** LightGBM (URL/Behavior), Transformers (Semantic), Hashing/Embeddings (Content).

## Setup & Installation
1.  **Clone the repository.**
2.  **Create a virtual environment:**
    ```powershell
    python -m venv .venv
    .venv/Scripts/Activate.ps1
    ```
3.  **Install dependencies:**
    ```powershell
    pip install -r requirements.txt
    ```

## Development Status
- [x] Phase 1: Project Initialization
- [x] Phase 2: Data Collection (URL & Metadata)
- [x] Phase 3: URL Feature Engineering
- [x] Phase 4: Semantic Analysis
- [x] Phase 5: Webpage Content Analysis
- [x] Phase 6: Behavioral Analysis
- [x] Phase 7: Model Training
- [x] Phase 8: Risk Aggregation
- [x] Phase 9: Chrome Extension
- [x] Phase 10: Evaluation & Hardening
- [x] Phase 11: Final Delivery

## Performance Metrics (Zero-Day Evaluation)
- **Accuracy**: ~86%
- **Avg. Latency**: <300ms
- **Detection Method**: Probabilistic Multi-Layer Analysis
- **Resilience**: Zero-day phishing ready (Time-based split validation)


