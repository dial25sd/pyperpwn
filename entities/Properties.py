from enum import Enum


class Rank(Enum):
    MANUAL = 0
    LOW = 1
    AVERAGE = 2
    NORMAL = 3
    GOOD = 4
    GREAT = 5
    EXCELLENT = 6

    @staticmethod
    def from_string(rank_name):
        try:
            return Rank[rank_name.upper().strip()]
        except KeyError:
            raise KeyError('no such rank defined: {}'.format(rank_name))

    @staticmethod
    def value_from_str(rank_name):
        return Rank.from_string(rank_name).value

    @staticmethod
    def is_valid(rank_name):
        try:
            return Rank.from_string(rank_name) is not None
        except KeyError:
            return False


class OS(Enum):
    LINUX = 0
    WINDOWS = 1
    MULTI = 2
    ALL = 3

    @staticmethod
    def from_string(os_name):
        try:
            return OS[os_name.upper().strip()]
        except KeyError:
            raise KeyError('no such operating system defined: {}'.format(os_name))

    @staticmethod
    def is_valid(os_name):
        try:
            return OS.from_string(os_name) is not None
        except KeyError:
            return False


class Speed(Enum):
    SLOW = 1
    MEDIUM = 2
    FAST = 3
