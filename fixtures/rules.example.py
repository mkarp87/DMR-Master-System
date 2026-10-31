"""Minimal, non-production HBlink bridge fixture for importer tests."""

BRIDGES = {
    "DEMO-BRIDGE": [
        {
            "SYSTEM": "REPEATER-DEMO",
            "TS": 1,
            "TGID": 1001,
            "ACTIVE": False,
            "TIMEOUT": 15,
            "TO_TYPE": "ON",
            "ON": [1001],
            "OFF": [4000],
            "RESET": [],
        },
        {
            "SYSTEM": "OPENBRIDGE-DEMO",
            "TS": 1,
            "TGID": 2001,
            "ACTIVE": True,
            "TIMEOUT": 15,
            "TO_TYPE": "NONE",
            "ON": [],
            "OFF": [],
            "RESET": [],
        },
    ]
}

UNIT = []
