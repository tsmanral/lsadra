"""
Regenerate docs/detection/scorecard.md and scorecard.json.

Scores every registered detection rule against the labelled demo corpus
(rules only, no trained model). Run it after changing a rule or the corpus and
commit the result; tests/test_detection_scorecard.py fails while the committed
files are out of date.

Usage:
    python scripts/detection_scorecard.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lsadra.detection.scorecard import write  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "detection"

if __name__ == "__main__":
    card = write(OUT)
    s = card["summary"]
    print(
        f"wrote {OUT}/scorecard.md: {s['scenarios_detected']}/{s['scenarios_with_attacks']} "
        f"scenarios detected, {s['benign_events_alerted']} benign events alerted"
    )
