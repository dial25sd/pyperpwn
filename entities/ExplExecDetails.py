import time
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import List

from core.ConnectionSupervisor import ExplExecDetectionMethod
from entities.Exploit import ExploitClass, Exploit
from entities.ReportEntry import ReportEntry
from entities.Vulnerability import Vulnerability


class ServiceStatus(IntEnum):
    UP_ACCESSIBLE = 0
    UP_FAILURE = 1
    DOWN = 2


class PortStatus(IntEnum):
    OPEN = 0
    FILTERED = 1
    CLOSED = 2


class ExplExecutionStatus(IntEnum):
    NOT_EXECUTED = -1
    EXPLOIT_EXECUTION_FAILED = 0
    EXPLOIT_EXECUTION_FINISHED = 1
    EXPLOIT_EXECUTED_GAINED_ACCESS = 2

    @staticmethod
    def from_str(name):
        try:
            return ExplExecutionStatus[name.upper().strip()]
        except KeyError:
            raise KeyError('No such execution status exists: {}.'.format(name))


# entity for representing the details of a single exploit execution

@dataclass
class ExplExecDetails:
    vuln_id: int
    expl_id: int
    vuln: Vulnerability
    vuln_type: str
    vuln_class: List[str]
    exploit: Exploit
    exploit_class: ExploitClass
    executed: bool
    execution_output: str
    execution_result: ExplExecutionStatus
    execution_detection_method: List[ExplExecDetectionMethod]
    timestamp: float
    impact: dict
    got_session: bool
    session_info: dict
    success: bool

    def __init__(self, **kwargs):
        self.vuln_id = kwargs.get('vuln_id', -1)
        self.expl_id = kwargs.get('expl_id', -1)
        self.vuln = kwargs.get('vuln', None)
        self.vuln_type = kwargs.get('vuln_type', '')
        self.vuln_class = kwargs.get('vuln_class', [])
        self.exploit = kwargs.get('exploit', None)
        self.exploit_class = kwargs.get('exploit_class', None)
        self.executed = kwargs.get('executed', False)
        self.execution_output = kwargs.get('execution_output', '')
        self.execution_result = kwargs.get('execution_result', [])
        self.execution_detection_method = kwargs.get('execution_detection_method', [])
        self.timestamp = time.time()
        self.impact = kwargs.get('impact', {})
        self.got_session = kwargs.get('got_session', False)
        self.session_info = kwargs.get('session_info', {})
        self.success = kwargs.get('success', False)

    def parse_vuln_intentions(self):
        if self.vuln_class is None:
            return ''
        intention_str = ''
        for int in self.vuln_class:
            int_name = getattr(int, 'name', 'None')
            intention_str = '{} {}'.format(intention_str, int_name)
        return intention_str

    def to_dict(self):
        new_impact = {}
        for k in self.impact.keys():
            new_impact[k] = self.impact[k].name
        self.impact = new_impact
        self.exploit_class = self.exploit_class.name if self.exploit_class else None
        self.execution_result = self.execution_result.name if self.execution_result else None
        return asdict(self)

    def to_report_entry(self):
        exploit_path = ''
        if self.exploit is not None:
            exploit_path = self.exploit.path
        if self.execution_detection_method is not None:
            self.execution_detection_method = list(set(self.execution_detection_method))
        return ReportEntry(vuln_id=self.vuln_id, entry_id=self.expl_id, exploit=exploit_path, cves=self.vuln.cve,
                           cvss=self.vuln.cvss, vuln_name=getattr(self.vuln, 'name', 'None'), success=self.success,
                           vuln_type=self.vuln_type, vuln_classification=self.parse_vuln_intentions(),
                           exploit_classification=getattr(self.exploit_class, 'name', 'None'),
                           execution_result=getattr(self.execution_result, 'name', 'None'), timestamp=self.timestamp,
                           impact=self.impact, session_info=self.session_info,
                           execution_detection_method=self.execution_detection_method,
                           solution_type=self.vuln.solution_type, execution_output=self.execution_output,
                           executed=self.executed)

    @staticmethod
    def get_correctly_typed_dict(self_dict):
        self_dict['exploit_class'] = ExploitClass.from_str(self_dict['exploit_class'])
        self_dict['execution_result'] = ExplExecutionStatus.from_str(self_dict['execution_result'])
        return self_dict

    def get_execution_result(self):
        if not self.executed:
            return ExplExecutionStatus.NOT_EXECUTED
        elif self.got_session:
            return ExplExecutionStatus.EXPLOIT_EXECUTED_GAINED_ACCESS
        elif self.has_execution_finished(exploit_output=self.execution_output) or len(
                self.execution_detection_method) > 0:
            return ExplExecutionStatus.EXPLOIT_EXECUTION_FINISHED
        return ExplExecutionStatus.EXPLOIT_EXECUTION_FAILED

    def has_execution_finished(self, exploit_output):
        if exploit_output.find("Exploit aborted") >= 0 or exploit_output.find("Exploit failed") >= 0:
            return False
        return True
