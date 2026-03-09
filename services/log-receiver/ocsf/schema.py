from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

OCSF_CLASSES = {
    2001: "security_finding",
    3002: "authentication",
    4001: "network_activity",
    4003: "file_activity",
    6003: "api_activity",
}


@dataclass(slots=True)
class OCSFEvent:
    class_uid: int
    class_name: str
    time: datetime
    severity_id: int  # 0=Unknown 1=Informational 2=Low 3=Medium 4=High 5=Critical
    status_id: int  # 1=Success 2=Failure 99=Other
    message: str
    metadata: dict[str, Any]  # version, product, etc.
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "time": self.time.isoformat(),
            "severity_id": self.severity_id,
            "status_id": self.status_id,
            "message": self.message,
            "metadata": self.metadata,
            "raw_data": self.raw_data,
        }
