import time

from entities.Properties import OS
from inout.ConsoleHandler import ConsoleHandler

NO_SESSION_FOUND = -1

WAIT_INTERVAL_FOR_SHELL_RESPONSE = 1


class SessionHandler:

    def __init__(self, msf_handler):
        self.console = ConsoleHandler('Sess.Handler')
        self.msf_handler = msf_handler

    # checks if a session has spawned by executing the given exploits.
    # return it's ID if possible, -1 otherwise
    def session_check(self, exploit_path, rport):
        exploit_path = "exploit/{}".format(exploit_path)
        self.console.info("Start Session checker for {}".format(exploit_path))
        sessions = self.msf_handler.get_all_sessions()
        if len(sessions) > 0:
            self.console.debug("\t session(s) discovered: {}".format(sessions))
            for session_id in sessions:
                if sessions[session_id]['via_exploit'] == exploit_path and sessions[session_id][
                    'session_port'] == rport:
                    self.console.info("\t Got session {} via exploit {}".format(session_id, exploit_path))
                    return int(session_id)
        self.console.warn("\t apparently no session spawned successfully.")
        return NO_SESSION_FOUND

    # gather useful information for a given remote session, based on the type of session and close session afterwards
    def gather_info(self, session_id, os):
        os = OS.from_string(os)
        session_id = str(session_id)
        session_obj = self.msf_handler.get_session_obj(session_id=session_id)
        shell_info = {'info': self.msf_handler.get_session_dict(session_id).get('info')}
        if self.msf_handler.get_session_dict(session_id=session_id).get('type') == 'meterpreter':
            self.console.debug('\t discovered a meterpreter shell')
            shell_info = self.run_default_meterpreter_cmds(session=session_obj, os=os, shell_info=shell_info)
        else:
            self.console.debug('\t discovered a normal session')
            shell_info = self.run_default_shell_cmds(shell=session_obj, os=os, shell_info=shell_info)
        self.exit_shell(shell=session_obj)
        self.close_single_session(session_id)
        self.console.debug("shell info: {}".format(shell_info))
        return shell_info

    # run special commands if a meterpreter session is present
    def run_default_meterpreter_cmds(self, session, os, shell_info):
        shell_info['meterpreter: getuid'] = self.run_single_shell_cmd(session, 'getuid')
        shell_info['meterpreter: route'] = self.run_single_shell_cmd(session, 'route')
        self.downgrade_meterpreter(session)
        shell_info = self.run_default_shell_cmds(session, os, shell_info=shell_info)
        self.exit_shell(session)
        return shell_info

    def run_default_shell_cmds(self, shell, os, shell_info):
        shell_info['whoami'] = self.run_single_shell_cmd(shell, 'whoami')
        if os == OS.LINUX:
            shell_info['uname -a'] = self.run_single_shell_cmd(shell, 'uname -a')
            shell_info['ifconfig'] = self.run_single_shell_cmd(shell, 'ifconfig')
        if os == OS.WINDOWS:
            shell_info['ipconfig'] = self.run_single_shell_cmd(shell, 'ipconfig')
        return shell_info

    def run_single_shell_cmd(self, shell, cmd):
        shell.write(cmd)
        try:
            time.sleep(WAIT_INTERVAL_FOR_SHELL_RESPONSE)
            shell_response = shell.read().strip()
            if shell_response != '':
                self.console.info("Received shell response to command '{}'.".format(cmd))
                self.console.debug("\t {}".format(shell_response))
                return shell_response
            else:
                self.console.info("Received empty shell response to command '{}'.".format(cmd))
                return None
        except KeyError:
            self.console.error("Unable to read data from console for command '{}'.".format(cmd))
            return None

    @staticmethod
    def only_empty_replies(shell_info):
        for cmd in shell_info:
            if shell_info.get(cmd) is not None:
                return False
        return True

    def exit_shell(self, shell):
        shell.write('exit')

    def downgrade_meterpreter(self, meterpreter_session):
        meterpreter_session.write('shell')
        time.sleep(WAIT_INTERVAL_FOR_SHELL_RESPONSE)
        meterpreter_session.read()

    # close a single session so that pyperpwn does not get confused while future executions of this exploit
    def close_single_session(self, session_id):
        self.exit_shell(self.msf_handler.get_session_obj(session_id=str(session_id)))
        self.console.info("Automatically closed session with id {}".format(session_id))

    # close all open remote sessions
    def close_all_sessions(self):
        sessions = self.msf_handler.get_all_sessions()
        for session_id in sessions:
            self.exit_shell(self.msf_handler.get_session_obj(session_id=session_id))
        self.console.info("Automatically closed {} sessions.".format(len(sessions)))
