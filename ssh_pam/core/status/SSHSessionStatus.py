from enum import Enum, unique


@unique
class SSHSessionStatus(Enum):
    CONNECTION_OPEN = 1
    AUTH_PENDING = 2
    CHANNEL_OPEN = 3
    SESSION_OPEN = 4
    SESSION_CLOSED = 5