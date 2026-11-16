from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event: str, alert_id: str, **data: Any) -> None:
        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "alert_id": alert_id,
            **data,
        }
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
