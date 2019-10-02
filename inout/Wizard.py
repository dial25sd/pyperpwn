import time
from argparse import ArgumentParser

from config import msf_default_config
from entities.Properties import Rank, OS, Speed
from inout.ConsoleHandler import ConsoleHandler


class Wizard:

    def __init__(self):
        self.print_greeting()
        self.console = ConsoleHandler("Wizard")

    def get_options(self):
        try:
            args = self.parse_args()
            args['vuln_source'] = self.check_delivered_value(args['vuln_source'], "Vulnerability Scanner Report Path",
                                                             (lambda x: True))
            args['expl_class'] = self.check_delivered_value(args['expl_class'], "Exploit Classification File Path",
                                                            (lambda x: True))
            args['rhost'] = self.check_delivered_value(args.get('rhost'), "Remote Host IP Address",
                                                       self.check_is_ip_addr)
            args['lhost'] = self.check_delivered_value(args.get('lhost'), "Local Host IP Address",
                                                       self.check_is_ip_addr)
            args['expl_rank'] = self.check_delivered_value(args.get('expl_rank'), "Exploit minimum rank",
                                                           (lambda x: Rank.is_valid(x)))
            args['expl_os'] = self.check_delivered_value(args.get('expl_os'), "Rhost operating system",
                                                         (lambda x: OS.is_valid(x)))
            args['xspeed'] = self.check_delivered_value(int(args.get('xspeed')), "Execution speed",
                                                        (lambda x: x in [1, 2, 3]))
            args['xspeed'] = Speed(args['xspeed'])
            args['espeed'] = self.check_delivered_value(int(args.get('espeed')), "Evaluation speed",
                                                        (lambda x: x in [1, 2, 3]))
            args['espeed'] = Speed(args['espeed'])
            args['lport'] = int(args['lport'])
            self.console.debug(args)
            if args.get('express'):
                self.console.warn(
                    "EXPRESS MODE IS ENABLED. Only as few prompts as necessary will appear. Please note that using the default values might lead to worse results.")
            return args
        except ValueError:
            raise ValueError

    @staticmethod
    def parse_args():
        parser = ArgumentParser(description="pyperpwn - Tool to verify the success of Metasploit's exploits",
                                epilog='With great power comes great responsibility. Use with care.')
        parser.add_argument("-p", "--password", dest="msfrpc_pwd", help="Connect to MSFRPCD using this password",
                            metavar="pwd", required=True)
        parser.add_argument("-a", "--msfhost", dest="msfrpc_host", help="Connect to MSFRPCD at this IP address",
                            metavar="ip", default=msf_default_config.get("host"))
        parser.add_argument("-P", "--port", dest="msfrpc_port", help="Connect to MSFRPCD at the specified port",
                            metavar="port", default=msf_default_config.get("port"))
        parser.add_argument("-o", "--os", dest="expl_os",
                            help="Use only exploits developed for this OS. Currently supports 'linux' and 'windows' and 'all'.",
                            metavar="name")
        parser.add_argument('--no-multi', dest='expl_os_multi', action='store_false',
                            help="Do not use universal exploits")
        parser.set_defaults(expl_os_multi=True)
        parser.add_argument("-r", "--rank", dest="expl_rank", help="Use only exploits with this minimum rank",
                            metavar="min-rank", default="manual")
        parser.add_argument("-v", "--vulns", dest="vuln_source", help="Read this report of a vulnerability scanner",
                            metavar="path")
        parser.add_argument("-c", "--class", dest="expl_class",
                            help="Read this file containing an exploit classification", metavar="path")
        parser.add_argument("-x", "--export", dest="report_path", help="Save the output report at this location",
                            metavar="path", default="hyper_pyper_report.csv")
        parser.add_argument("-t", "--target", dest="rhost", help="IP address of the remote host to be tested",
                            metavar="ip")
        parser.add_argument("-l", "--lhost", dest="lhost", help="IP address of the local host running this script",
                            metavar="ip")
        parser.add_argument("-w", "--lport", dest="lport", help="Port number to be used for Session Handlers",
                            metavar="port", default="5678")
        parser.add_argument('-e', dest='exec_expl', action='store_true',
                            help="Only actually execute exploits if this flag is set.")
        parser.add_argument("-xs", "--execspeed", dest="xspeed",
                            help="The speed level to be used for exploit execution. Can be either 1, 2 or 3. (the higher, the faster)",
                            metavar="1|2|3", default="3")
        parser.add_argument("-es", "--evalspeed", dest="espeed",
                            help="The speed level to be used for success evaluation. Can be either 1, 2 or 3. (the higher, the faster)",
                            metavar="1|2|3", default="3")
        parser.add_argument("-XX", "--express", dest="express", action='store_true',
                            help="Execute the tool using default values and  without any prompts.")
        parser.add_argument("-XA", "--execall", dest="execall", action='store_true',
                            help="Don't ask whether exploits should be executed.", )
        parser.set_defaults(exec_expl=False)
        parser.set_defaults(express=False)
        parser.set_defaults(execall=False)
        args = vars(parser.parse_args())
        return args

    # check if the provided param value is valid, judging by the given validation function
    def check_delivered_value(self, val, name, validation_fun):
        if val is None:
            val = self.read_option_value(name)
        if validation_fun(val):
            self.console.debug("setting '{}' to '{}'".format(name, val))
            return val
        self.console.error("\t no valid value provided for '{}'".format(name))
        raise ValueError

    def read_option_value(self, option_name):
        param_value = self.console.prompt("Required option [{}] not specified. Enter a value".format(option_name))
        if len(param_value) == 0:
            self.console.error("Cannot work without this parameter...")
        return param_value

    @staticmethod
    def check_is_ip_addr(ip):
        parts = ip.split('.')
        if len(parts) == 4:
            for part in parts:
                if int(part) < 0 or int(part) > 255:
                    return False
            return True
        return False

    # return the path of the manually selected payload, or None for default payload
    def get_payload(self, payload_paths):
        change_payload = self.console.prompt(
            "Do you want to change the default payload ({} alternatives available)? [y/n]".format(
                len(payload_paths) - 1))
        if change_payload == 'y':
            self.console.info("\t Available payloads:")
            for i in range(len(payload_paths)):
                self.console.info("\t  ({})\t{}".format(i, payload_paths[i]))
            try:
                new_payload = int(
                    self.console.prompt("Enter the number of the payload to use instead (blank for default)"))
            except ValueError:
                self.console.debug("No number provided. Default payload will be used.")
                return None
            if new_payload in range(len(payload_paths)):
                return payload_paths[new_payload]
            self.console.warn("Invalid value provided. Default payload will be used.")
        return None

    # prompt the user for a new value for a given module param
    def read_param_value_from_console(self, param_name, current_value):
        param_value = self.console.prompt(
            "\t [{}], current value: '{}'. Enter a new value (leave blank for default)".format(param_name,
                                                                                               str(current_value)))
        if len(param_value) > 0:
            self.console.debug("\t setting param {} = {}".format(param_name, param_value))
            return param_value
        return None

    def continue_last_exec(self, ip, exec_state):
        if exec_state is None:
            self.console.debug('No matching previous unfinished execution found.')
            return False
        self.console.info("Found an unfinished execution against {}, started at {}".format(ip, time.strftime(
            '%Y-%m-%d %H:%M %Z', time.localtime(exec_state.start_time))))
        continue_exec = self.console.prompt('Do you want to continue? "n" discards the data. [y/n]') == 'y'
        if continue_exec is True:
            self.console.debug('Continue previously unfinished execution {}'.format(exec_state))
        return continue_exec

    def generate_report_now(self):
        return self.console.prompt(
            "Save this execution for later [c]ontinuation, [g]enerate a report now or e[x]it at any cost?")

    def exec_expl_against_public_addr(self, rhost):
        return self.console.prompt(
            "Detected public IP address. Do you want to execute the exploit against {}? [y/n]".format(rhost)) == 'y'

    def exec_expl(self, expl_path, rhost):
        return self.console.prompt(
            "Do you want to execute exploit '{}' against {}? [y/n]".format(expl_path, rhost)) == 'y'

    def print_expl_exec_info(self, expl_path, is_repetition):
        if not is_repetition:
            self.console.empty(1)
            self.console.caption("Exploit '{}' will now be executed".format(expl_path))
        else:
            self.console.empty(1)
            self.console.warn("Exploit '{}' will be re-executed since it hasn't been successful.".format(expl_path))

    def print_greeting(self):
        print("\n====================================================================================\n")
        print(" $$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  $$\  $$\  $$\ $$$$$$$\  \n" +
              "$$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ | $$ | $$ |$$  __$$\ \n"
              "$$ /  $$ |$$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|$$ /  $$ |$$ | $$ | $$ |$$ |  $$ |\n"
              "$$ |  $$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ | $$ | $$ |$$ |  $$ |\n"
              "$$$$$$$  |\$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |\$$$$$\$$$$  |$$ |  $$ |\n"
              "$$  ____/  \____$$ |$$  ____/  \_______|\__|      $$  ____/  \_____\____/ \__|  \__|\n"
              "$$ |      $$\   $$ |$$ |                          $$ |                              \n"
              "$$ |      \$$$$$$  |$$ |                          $$ |                              \n"
              "\__|       \______/ \__|                          \__|                              \n")
        print("====================================================================================\n")
        print("Welcome to pyperpwn!\nPlease restart the MSFRPC daemon everytime you restart this application.\n")
        print("====================================================================================\n")

    def print_vuln_caption(self, vuln_name, cve, cvss):
        self.console.empty(2)
        self.console.caption("NOW TREATING VULNERABILITY: '{}' (CVSS: {})".format(vuln_name, cvss))
        self.console.empty(1)
