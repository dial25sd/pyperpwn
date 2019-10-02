#!env/bin/python

import os
import sys
import time

from config import ExecSpeed
from core.ExploitExecutor import ExploitExecutor
from core.ExploitMatcher import ExploitMatcher
from core.SuccessChecker import SuccessChecker
from core.SuccessEvaluator import SuccessEvaluator
from db.DBHandler import DBHandler
from entities.ExecStatus import ExecStatus
from entities.ExplExecDetails import ExplExecDetails, ExplExecutionStatus
from entities.Exploit import Exploit, ExplExecDetectionMethod
from entities.Vulnerability import Vulnerability, VulnType
from inout.CSVWriter import CSVWriter
from inout.CVEDetailParser import CVEDetailParser
from inout.ConsoleHandler import ConsoleHandler
from inout.ExplClassificationReader import ExplClassificationReader
from inout.VulnReportReader import VulnReportReader
from inout.Wizard import Wizard
from msf.MsfHandler import MsfHandler
from msf.SessionHandler import SessionHandler, NO_SESSION_FOUND

console = ConsoleHandler("pyperpwn")

db = None
session_handler = None
exec_state = None


def main(args):
    global db
    global exec_state
    global session_handler

    msf_handler = get_msf_handler()
    db = get_db_handler(msf_handler=msf_handler)

    exec_state = db.take_matching_exec_status(args.get('rhost'))
    db.build_expl_coll()
    ExplClassificationReader(db_handler=db).write_to_db(args.get('expl_class'))

    cve_parser = CVEDetailParser(db_handler=db)
    exploit_matcher = ExploitMatcher(db_handler=db)
    exploit_executor = ExploitExecutor(msf_handler=msf_handler, wizard=wizard)
    session_handler = SessionHandler(msf_handler=msf_handler)

    continue_execution = wizard.continue_last_exec(args.get('rhost'), exec_state)
    if not continue_execution:
        db.clear_db_on_start()
        exec_state = ExecStatus(ip=args.get('rhost'), start_time=time.time())
        vulns = read_vulns(file_path=args.get('vuln_source'))
        db.save_vulns(vulns)
        vulns_range = range(len(vulns))
    else:
        vulns = db.get_vulns()
        vulns_range = range(len(vulns))[exec_state.last_vuln + 1:]

    vulns = Vulnerability.sort_vulns(vulns)

    # first iterate over all vulnerabilites that have been read from the report
    for i in vulns_range:
        vuln = vulns[i]
        wizard.print_vuln_caption(vuln_name=vuln.name, cve=vuln.cve, cvss=vuln.cvss)
        vuln_type = cve_parser.get_cve_details(vuln.cve)
        vuln_class = VulnType.types_to_intentions(console, vuln_type)
        vuln.exploits = exploit_matcher.find_exploits_for_vuln(vuln=vuln, os_multi=args.get('expl_os_multi'),
                                                               rank=args.get('expl_rank'), os=args.get('expl_os'))
        exec_details = ExplExecDetails(vuln=vuln, vuln_type=vuln_type, vuln_id=exec_state.last_vuln + 2,
                                       expl_id=exec_state.last_expl + 2, vuln_class=vuln_class)

        if not exploits_avail_for_vuln(vuln=vuln, exec_details=exec_details):
            continue
        console.info("All exploits found: {}".format(Exploit.print_expl_list(vuln.exploits)))

        # second iterate over all found exploits for the given vuln
        for expl in vuln.exploits:
            current_expl_repetition_count = 0
            exec_details = ExplExecDetails(vuln=vuln, vuln_type=vuln_type, vuln_id=exec_state.last_vuln + 2,
                                           expl_id=exec_state.last_expl + 2, vuln_class=vuln_class)

            while current_expl_repetition_count < ExecSpeed[args.get('xspeed').name].value[0]:
                current_expl_repetition_count += 1
                wizard.print_expl_exec_info(expl_path=expl.path, is_repetition=(current_expl_repetition_count != 1))
                expl_class = get_expl_class(expl_path=expl.path)
                exec_details.exploit = expl
                exec_details.exploit_class = expl_class
                additional_params = {}

                if args.get('exec_expl'):
                    additional_params = exploit_executor.check_exploit_params(expl)
                    exec_expl(express=args.get('express'), exploit=expl, exec_details=exec_details, vuln=vuln,
                              executor=exploit_executor, additional_params=additional_params)
                else:
                    console.warn("Exploits won't be executed as the execute flag has not been set.")

                if exec_details.executed:
                    findings = []
                    session = session_handler.session_check(exploit_path=expl.path, rport=vuln.port)
                    exec_details.got_session = session != NO_SESSION_FOUND
                    exec_details.execution_result = exec_details.get_execution_result()
                    console.debug("result: {}".format(exec_details.execution_result))
                    if exec_details.execution_result is not ExplExecutionStatus.EXPLOIT_EXECUTION_FAILED:
                        uri = get_webapp_uri(msf_handler=msf_handler, expl=expl, additional_params=additional_params)
                        findings = SuccessChecker().check(speed=args.get('espeed'), rhost=args.get('rhost'),
                                                          port=vuln.port, uri=uri)
                        if session > 0:
                            post_session_actions(details=exec_details, session=session)
                    else:
                        console.warn("Exploit execution failed.")
                    post_exec_actions(details=exec_details, expl_class=expl_class, findings=findings)

                exec_state.expl_exec_details.append(exec_details)
                exec_state.last_expl += 1
                if exec_details.success is True or exec_details.executed is False:
                    break
                console.info("Waiting intentionally...")
                time.sleep(ExecSpeed[args.get('xspeed').name].value[1])
        exec_state.last_vuln += 1
    successful_exit()


def graceful_exit():
    print('')
    console.empty(1)
    console.warn("Gracefully stopping application.")
    if session_handler is not None:
        session_handler.close_all_sessions()
    next_action = wizard.generate_report_now()
    if next_action == 'g':
        successful_exit()
    elif next_action == 'c':
        console.info('Saving application state...')
        if db is not None and exec_state is not None:
            db.save_exec_status(exec_state)
    else:
        console.warn("Forced exit.")


def successful_exit():
    db.remove_cached_data()
    console.empty(1)
    console.info('Application execution successfully finished.')
    generate_report()


def get_msf_handler():
    try:
        return MsfHandler(host=args.get('msfrpc_host'), port=args.get('msfrpc_port'), pwd=args.get('msfrpc_pwd'))
    except ConnectionError:
        console.error("Cannot connect to MSFRPC, aborting.")
        raise ConnectionError


def get_db_handler(msf_handler):
    try:
        return DBHandler(msf_handler=msf_handler)
    except ConnectionError:
        instant_exit(friendly=False)


def generate_report():
    console.info("Creating result CSV file...")
    CSVWriter().write_csv(report_entries=exec_state.get_report_entries(), path=args['report_path'])


def instant_exit(friendly):
    if console is not None:
        if friendly:
            console.info("Execution finished successfully.")
        else:
            console.error("Abort.")
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)


def read_vulns(file_path):
    vuln_reader = VulnReportReader()
    try:
        return vuln_reader.read_csv(path=file_path)
    except (FileNotFoundError, KeyError):
        instant_exit(friendly=False)


def exploits_avail_for_vuln(vuln, exec_details):
    if vuln.exploits is None or len(vuln.exploits) == 0:
        console.warn("No exploits available for vulnerability {}, proceeding...".format(vuln.name))
        exec_state.expl_exec_details.append(exec_details)
        exec_state.last_expl += 1
        exec_state.last_vuln += 1
        return False
    return True


def exec_expl(executor, express, exploit, exec_details, vuln, additional_params):
    default_params = {'rhost': args['rhost'], 'rport': vuln.port, 'lhost': args['lhost'], 'lport': args['lport']}
    if not express:
        exec_res = executor.execute_exploit(expl=exploit, params=default_params, express=args.get('express'),
                                            additional_params=additional_params, execall=args.get('execall'))
        exec_details.execution_output = exec_res.get('output')
        exec_details.execution_detection_method = exec_res.get('detection_method')
        exec_details.executed = exec_details.execution_output is not None


def get_expl_class(expl_path):
    global db
    expl_class = db.get_expl_class(expl_path)
    if expl_class is not None:
        console.debug("retrieved exploit class '{}' for exploit '{}'".format(expl_class.name, expl_path))
        return expl_class
    else:
        console.warn("Unable to retrieve exploit classification for exploit {}.".format(expl_path))
        return None


def get_webapp_uri(expl, additional_params, msf_handler):
    # try to get the value set by the user
    if 'TARGETURI' in additional_params:
        return additional_params['TARGETURI']
    elif 'URI' in additional_params:
        return additional_params['URI']
    # if unchanged get the default value
    elif expl.contains_required_param('TARGETURI'):
        return msf_handler.get_exploit(expl.path)['TARGETURI']
    elif expl.contains_required_param('URI'):
        return msf_handler.get_exploit(expl.path)['URI']
    return None


def post_exec_actions(details, findings, expl_class):
    evaluator = SuccessEvaluator()
    details.impact = evaluator.merge_findings(findings=findings)
    details.success = evaluator.was_expl_successful(intention=expl_class, details=details)


def post_session_actions(details, session):
    details.execution_detection_method.append(ExplExecDetectionMethod.DETECTED_SHELL)
    details.session_info = session_handler.gather_info(session, os=args.get('expl_os'))
    if not SessionHandler.only_empty_replies(details.session_info):
        console.debug("not all session replies are empty")
        details.execution_detection_method.append(ExplExecDetectionMethod.COMMUNICATED_WITH_SHELL)


if __name__ == '__main__':
    args = None
    if sys.version_info[0] < 3:
        raise EnvironmentError('Pyperpwn requires Python v3')
    try:
        wizard = Wizard()
        try:
            args = wizard.get_options()
        except ValueError as err:
            console.error(err)
            instant_exit(friendly=False)
        try:
            main(args)
        except ConnectionError:
            instant_exit(friendly=False)
    except KeyboardInterrupt:
        if args is not None:
            graceful_exit()
        else:
            console.error("cannot create report because of missing input.")
    instant_exit(friendly=True)
