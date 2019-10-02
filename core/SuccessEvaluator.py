from entities.ExplExecDetails import ServiceStatus
from entities.Exploit import ExploitClass
from inout.ConsoleHandler import ConsoleHandler


class SuccessEvaluator:

    def __init__(self):
        self.console = ConsoleHandler('SuccessEval')

    def merge_findings(self, findings):
        self.console.debug("all findings: {}".format(findings))
        complete_finding = {}
        for finding in findings:
            for key in finding.keys():
                try:
                    if finding[key].value > complete_finding[key].value:
                        complete_finding[key] = finding[key]
                except (KeyError, AttributeError) as err:
                    complete_finding[key] = finding[key]
        self.console.debug("merged findings: {}".format(complete_finding))
        return complete_finding

    def has_done_damage(self, finding):
        self.console.debug(finding)
        vals = [finding[key] for key in finding.keys()]
        for val in vals:
            if val.value > ServiceStatus.UP_ACCESSIBLE.value:
                return True
        return False

    def was_expl_successful(self, intention, details):
        has_done_damage = self.has_done_damage(details.impact)
        expl_executed_on_target = len(details.execution_detection_method) > 0
        self.console.debug(
            "Evaluating success of exploit: session? {}, has done damage? {}".format(details.got_session,
                                                                                     has_done_damage))
        if intention == ExploitClass.INTRUSIVE_DESTRUCTIVE:
            if has_done_damage or expl_executed_on_target:
                return True
        if intention == ExploitClass.INTRUSIVE:
            if not has_done_damage and expl_executed_on_target:
                return True
        if intention == ExploitClass.NOT_INTRUSIVE:
            if expl_executed_on_target and not has_done_damage:
                return True
        return False
