from typing import Any


def build_ism_policy(retention_days: int) -> dict[str, Any]:
    """Build OpenSearch ISM hot→warm→delete policy.

    - hot: rollover daily or at 10M docs (active writes, fresh data)
    - warm: read_only + force_merge to 1 segment (compressed, still searchable)
    - delete: at retention_days boundary
    """
    warm_after_days = 30
    delete_after_days = retention_days

    return {
        "policy": {
            "description": f"SkausWatch SIEM log lifecycle: 30d hot, delete at {delete_after_days}d",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {
                            "rollover": {
                                "min_index_age": "1d",
                                "min_doc_count": 10_000_000,
                            }
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "warm",
                            "conditions": {"min_index_age": f"{warm_after_days}d"},
                        }
                    ],
                },
                {
                    "name": "warm",
                    "actions": [
                        {"read_only": {}},
                        {"force_merge": {"max_num_segments": 1}},
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": f"{delete_after_days}d"},
                        }
                    ],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
        }
    }
