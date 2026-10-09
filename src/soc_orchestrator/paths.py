"""Repository-relative paths for the bundled policy and samples."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sample_feed_path() -> Path:
    return ROOT / "samples" / "ti_feed.json"


def sample_events_path() -> Path:
    return ROOT / "samples" / "events.jsonl"
