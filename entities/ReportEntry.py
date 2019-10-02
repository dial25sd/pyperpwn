from dataclasses import dataclass, asdict


@dataclass
class ReportEntry:
    vuln_id: int
    entry_id: int
    cves: str
    cvss: float
    vuln_name: str
    vuln_type: str
    vuln_classification: str
    exploit: str
    executed: bool
    exploit_classification: str
    execution_result: str
    execution_detection_method: []
    timestamp: float
    impact: []
    session_info: []
    success: bool
    execution_output: str
    solution_type: str

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def get_field_names():
        return ['entry_id', 'vuln_id', 'timestamp', 'vuln_name', 'exploit', 'cves', 'cvss', 'vuln_type',
                'vuln_classification', 'executed', 'exploit_classification', 'execution_result',
                'execution_detection_method', 'impact', 'session_info', 'success', 'execution_output', 'solution_type']

    @staticmethod
    def get_column_names():
        return ['Entry ID', 'Vuln ID', 'Timestamp', 'Vulnerability Name', 'Exploit', 'CVEs', 'CVSS',
                'Vulnerability Type', 'Vulnerability Classification', 'Executed', 'Exploit Classification',
                'Execution Result', 'Execution Detection Method', 'Execution Impact', 'Session Info', 'Success',
                'Output', 'Solution Type']
