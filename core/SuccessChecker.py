import os
import platform
import subprocess
import time

import nmap

from config import EvalSpeed
from entities.ExplExecDetails import ServiceStatus, PortStatus
from inout.ConsoleHandler import ConsoleHandler

HTTP_CHECK_MAX_TIME = 15


class SuccessChecker:

    def __init__(self):
        self.console = ConsoleHandler("SuccessCheck")

    def check(self, speed, rhost, port, uri):
        res = []
        iterations = EvalSpeed[speed.name].value[0]
        interval = EvalSpeed[speed.name].value[1]
        for iteration in range(iterations):
            self.console.info("Run #{} of success checker".format(iteration))
            check_result = {'ping': self.ping_check(rhost)}
            check_result['nmap'] = self.nmap_check(host=rhost, port=port)
            if uri is not None:
                url = "{}:{}{}".format(rhost, str(port), uri)
                check_result['http'] = self.http_check(url=url)
            res.append(check_result)
            self.console.info("\t intentionally waiting...")
            time.sleep(interval)
        self.console.debug(res)
        return res

    def ping_check(self, rhost):
        self.console.debug("\t start PING checker")
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', rhost]
        with open(os.devnull, 'w') as DEVNULL:
            res = subprocess.call(command, stderr=DEVNULL, stdout=DEVNULL)
        if res == 0:
            self.console.debug("\t \t host still up and running.")
            return ServiceStatus.UP_ACCESSIBLE
        else:
            self.console.debug("\t \t host dead.")
            return ServiceStatus.DOWN

    def http_check(self, url):
        self.console.debug("\t start HTTP checker for {}".format(url))
        command = ['curl', url, "-m", "{}".format(HTTP_CHECK_MAX_TIME)]
        with open(os.devnull, 'w') as DEVNULL:
            res = subprocess.call(command, stderr=DEVNULL, stdout=DEVNULL)
        if res == 0:
            self.console.debug("\t \t web server still up and running.")
            return ServiceStatus.UP_ACCESSIBLE
        else:
            self.console.info("\t \t web server dead.")
            return ServiceStatus.DOWN

    def nmap_check(self, host, port):
        self.console.debug("\t start nmap checker...")
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, ports=str(port))
        info = scanner.scaninfo()
        err = info.get('error')
        try:
            del info['error']
        except KeyError:
            pass
        self.console.debug(info)
        if err is not None:
            self.console.debug("\t \t {}".format(err))
        try:
            state = scanner[host]['tcp'][port]['state']
            self.console.debug("\t \t -> Port is {}".format(state))
        except KeyError:
            self.console.warn("\t \t unable to retrieve nmap output: {}.".format(info))
            return None
        try:
            state_obj = PortStatus[state.strip().upper()]
        except KeyError:
            self.console.error("Invalid value for Port State: {}".format(state))
            return PortStatus.CLOSED
        return state_obj
