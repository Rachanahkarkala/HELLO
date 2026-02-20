# MuleSight

MuleSight is a graph-based financial forensics web app for detecting money muling rings from transaction CSV uploads.

## Features
- CSV upload with required schema validation.
- Premium glassmorphism dashboard with animated metric cards and polished interaction states.
- Directed graph visualization of account-to-account money flow.
- Automatic detection of:
  - Circular routing cycles (length 3-5)
  - Smurfing fan-in and fan-out patterns (10+ accounts in 72 hours)
  - Layered shell chains (3+ hops with low-activity intermediates)
- Suspicious account scoring (0-100), sorted descending.
- Fraud ring summary table in UI.
- Downloadable JSON result in required structure.

## Tech stack
- HTML/CSS/JavaScript (vanilla)
- PapaParse for CSV parsing
- vis-network for graph rendering

## Run locally
```bash
python3 -m http.server 8000
```
Open `http://localhost:8000`.

## Input CSV format
Must include columns:
- `transaction_id`
- `sender_id`
- `receiver_id`
- `amount`
- `timestamp` (`YYYY-MM-DD HH:MM:SS`)

## JSON output format
The download uses:
- `suspicious_accounts`: account_id, suspicion_score, detected_patterns, ring_id
- `fraud_rings`: ring_id, member_accounts, pattern_type, risk_score
- `summary`: total_accounts_analyzed, suspicious_accounts_flagged, fraud_rings_detected, processing_time_seconds

## Notes
- Suspicious nodes are visually distinct by size, border, and highlight color.
- Ring nodes are color-grouped where possible.
- Graph tooltips show node-level suspicious status.
