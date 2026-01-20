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

## Setup
*(Instructions to be added)*
