from dataclasses import dataclass, asdict
from typing import List

from dacite import from_dict

from entities.ExplExecDetails import ExplExecDetails


# entity for handling application's current execution status, mainly for saving and restoring the application's state

@dataclass
class ExecStatus:
    expl_exec_details: List[ExplExecDetails]
    ip: str
    start_time: float
    end_time: float
    last_vuln: int  # the last finished treated vulnerability
    last_expl: int  # the last finished executed exploit

    def __init__(self, **kwargs):
        self.expl_exec_details = kwargs.get('expl_exec_details', [])
        self.ip = kwargs.get('ip', '')
        self.start_time = kwargs.get('start_time', 0.0)
        self.end_time = kwargs.get('end_time', 0.0)
        self.last_vuln = kwargs.get('last_vuln', -1)
        self.last_expl = kwargs.get('last_vuln', -1)

    def to_dict(self):
        exec_details = []
        if self.expl_exec_details:
            for entry in self.expl_exec_details:
                exec_details.append(entry.to_dict())
            self.expl_exec_details = exec_details
        return asdict(self)

    @staticmethod
    def from_dict(data):
        details = []
        for detail in data['expl_exec_details']:
            details.append(ExplExecDetails.get_correctly_typed_dict(detail))
        data['expl_exec_details'] = details
        return from_dict(data_class=ExecStatus, data=data)

    def get_report_entries(self):
        entries = []
        for detail in self.expl_exec_details:
            entries.append(detail.to_report_entry())
        return entries
