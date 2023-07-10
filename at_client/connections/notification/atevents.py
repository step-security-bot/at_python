from enum import Enum
from typing import Dict, Set

class AtEventType(Enum):
        NONE = 0
        SHARED_KEY_NOTIFICATION = 1
        UPDATE_NOTIFICATION = 2
        DELETE_NOTIFICATION = 3
        UPDATE_NOTIFICATION_TEXT = 4
        STATS_NOTIFICATION = 5
        MONITOR_HEARTBEAT_ACK = 6
        MONITOR_EXCEPTION = 7
        DECRYPTED_UPDATE_NOTIFICATION = 8
        USER_DEFINED = 9

class AtEvent:
    def __init__(self, event_type, event_data):
        self.event_type = event_type
        self.event_data = event_data
