from enum import Enum

log_config = {
    "debug": False
}

db_config = {
    "diff_range": 10,
    "host": 'localhost',
    "port": 27017
}

msf_default_config = {
    "host": "127.0.0.1",
    "port": "55553"
}

cve_details_config = {
    "url": "https://www.cvedetails.com/cve/"
}

exploit_search_config = {
    "min_score": 1.25,
    "max_count_by_name": 3
}


class Colours:
    warn = "\033[1m\033[33m"
    error = "\033[1m\033[91m"
    prompt = "\033[1m\033[36m"
    info = "\033[1m\033[32m"
    debug = "\033[36m"
    background = "\033[36m"
    end = "\033[0m"


class EvalSpeed(Enum):
    SLOW = (4, 15)
    MEDIUM = (3, 10)
    FAST = (2, 5)


class ExecSpeed(Enum):
    SLOW = (5, 15)
    MEDIUM = (3, 10)
    FAST = (1, 5)
