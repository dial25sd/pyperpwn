import requests
from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError, MsfAuthError
from urllib3.exceptions import NewConnectionError, MaxRetryError

from inout.ConsoleHandler import ConsoleHandler


class MsfHandler:

    def __init__(self, host, port, pwd):
        self.console = ConsoleHandler('MsfHandler')
        self.msfrpc_client = self.get_msfrpc_client(host=host, port=port, pwd=pwd)
        if self.msfrpc_client is None:
            raise ConnectionError('Cannot connect to MSFRPC')

    # start the client and return it
    def get_msfrpc_client(self, host, port, pwd):
        self.console.info("Connecting to MSFRPC server...")
        msf_client = None
        try:
            msf_client = MsfRpcClient(password=pwd, port=port, server=host, ssl=False)
            self.console.info("\t Successfully connected to MSFRPC at {}:{}".format(host, port))
            msf_console = MsfRpcConsole(msf_client, cb=MsfHandler.read_output)
        except (ConnectionRefusedError, NewConnectionError, MaxRetryError, requests.exceptions.ConnectionError) as e:
            self.console.error(
                "\t Connection to MSFRPC at {}:{} couldn't be established: {}!".format(host, port, type(e).__name__))
        except MsfAuthError:
            self.console.error("MSFRPC Authentication error.")
        except MsfRpcError:
            self.console.error("\t Error while logging in to MSFRPC!")
        return msf_client

    @staticmethod
    def read_output(console_data):
        console = ConsoleHandler('MsfHandler')
        console.debug("Main console received output: {}".format(console_data))

    def get_all_exploits(self):
        return self.msfrpc_client.modules.exploits

    # get reference to metasploit exploit object
    def get_exploit(self, expl_path):
        try:
            expl = self.msfrpc_client.modules.use('exploit', expl_path)
            return expl
        except (UnicodeDecodeError, requests.exceptions.ConnectionError):
            ConsoleHandler("ExploitParser").error("\t error decoding exploit module")
            return None

    def get_payload(self, payload_path):
        return self.msfrpc_client.modules.use('payload', payload_path)

    def execute_exploit_with_output(self, cid, exploit, payload):
        return self.msfrpc_client.consoles.console(cid).run_module_with_output(exploit, payload=payload)

    def get_new_console_with_id(self):
        return self.msfrpc_client.consoles.console().cid

    def get_all_sessions(self):
        return self.msfrpc_client.sessions.list

    def get_session_dict(self, session_id):
        return self.get_all_sessions()[session_id]

    def get_session_obj(self, session_id):
        return self.msfrpc_client.sessions.session(session_id)
