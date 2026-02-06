# AI-Phishing Detection - Clean Project Structure (Phase 1)

```
AI-Phishing Detection/
├── data/
│   └── external/                    # Phase 1 datasets
│       ├── phishtank.csv           # Full PhishTank blacklist
│       ├── phishtank_simple.csv    # Processed blacklist (5000 URLs)
│       ├── top-1m.csv              # Full Tranco list
│       ├── tranco.zip              # Downloaded archive
│       └── tranco_whitelist.csv    # Top 1M legitimate domains
│
├── src/
│   ├── extension/                   # Chrome Extension (Phase 1)
│   │   ├── manifest.json
│   │   ├── background.js
│   │   ├── content.js
│   │   ├── popup.html
│   │   ├── popup.js
│   │   └── icon.png
│   │
│   ├── features/
│   │   ├── __init__.py
│   │   └── rule_engine.py          # PhishTank + Tranco lookups
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── app.py                  # Flask API (Phase 1: rule-based)
│   │   └── inference.py            # (Reserved for Phase 2 ML)
│   │
│   └── utils/
│       ├── __init__.py
│       ├── dataset_downloader.py   # PhishTank + Tranco downloader
│       ├── data_collector.py       # (Reserved for Phase 2)
│       └── data_storage.py         # (Reserved for Phase 2)
│
├── analyze_url.py                   # URL testing utility
├── test_api_rules.py               # API testing script
├── requirements.txt                # Python dependencies
└── README.md                       # Project documentation

## Removed (Non-Phase 1):
✅ data/features/          - Duplicate folder (Phase 2)
✅ data/paper_features/    - Research paper features (not needed)
✅ data/processed/         - Duplicate folder (Phase 2)
✅ data/raw/               - Duplicate folder (Phase 2)
✅ src/features/paper_features.py      - Research implementation
✅ src/features/semantic_features.py   - Phase 4
✅ src/features/content_features.py    - Phase 4
✅ src/features/behavioral_features.py - Phase 5
✅ src/features/url_features.py        - Phase 2
✅ src/features/process_*.py           - Phase 2
✅ src/models/train_*.py               - Phase 2
✅ src/models/evaluate_model.py        - Phase 2
✅ src/models/inference_paper.py       - Research code
✅ src/models/*.joblib                 - Old models
✅ basepaper/              - Research paper
✅ tests/                  - Old tests
✅ docs/                   - Empty folder
✅ debug_*.py              - Debug scripts (10+ files)
```

## Phase 1 Status: ✅ COMPLETE
- ✅ PhishTank blacklist (5,000 URLs)
- ✅ Tranco whitelist (1M domains)
- ✅ Rule Engine for instant lookups
- ✅ Flask API with rule-based validation
- ✅ Chrome Extension ready

## To Run:
```bash
# Download/update datasets
python -m src.utils.dataset_downloader

# Start backend
python -m src.models.app

# Test a URL
python analyze_url.py
```
