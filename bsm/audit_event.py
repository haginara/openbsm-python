import os
from typing import List
from collections import namedtuple

from .bsm_h import AUDIT_EVENT_FILE


AUDIT_EVENT = namedtuple("AuditEvent", "event_id identifier entry flags")


def get_audit_events() -> List[AUDIT_EVENT]:
    audit_events = {}
    with open(AUDIT_EVENT_FILE, "r") as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            line = line.replace("::", ":")
            event = line.split(":")
            if len(event) == 4:
                event[0] = int(event[0])
                audit_events[event[0]] = AUDIT_EVENT(*event)

    return audit_events
