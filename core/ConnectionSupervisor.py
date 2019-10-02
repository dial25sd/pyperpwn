import subprocess
from dataclasses import dataclass
from enum import Enum
from threading import Thread

from entities.Exploit import ExplExecDetectionMethod
from inout.ConsoleHandler import ConsoleHandler


class ConnectionDirection(Enum):
    UNDETERMINED = 0
    HOST_TO_TARGET = 1
    TARGET_TO_HOST = 2


@dataclass
class Connection:
    direction: ConnectionDirection
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int


class ConnectionSupervisor(Thread):
    proc = None

    detected_syn = False
    detected_synack = False
    syn_seq = -1
    synack_seq = -1

    detected_exploit_delivery = False
    detected_payload_delivery = False
    detected_payload_connection = False

    expl_exec_detection_method: ExplExecDetectionMethod

    def __init__(self, lhost, rhost, rport, lport, is_reverse_payload, is_staged_payload, results):
        Thread.__init__(self)
        self.console = ConsoleHandler('ConnSuperv')
        if lhost is None or rhost is None or lhost == '' or rhost == '':
            raise AttributeError('You need to specify a value for rhost and lhost.')
        self.lhost = lhost
        self.rhost = rhost
        self.rport = rport
        self.lport = lport
        self.is_reverse_payload = is_reverse_payload
        self.is_staged_payload = is_staged_payload
        self.file = open("tcpdump_log.txt", "w")
        self.results = results

    # Start the subprocess
    def run(self):
        self.console.info("Start to capture network traffic with host {}...".format(self.rhost))
        self.proc = subprocess.Popen(['tcpdump', '-l', 'host', self.rhost, '-nn', '-S'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # -nn = don't convert addresses and port numbers to names
        # -S = print absolute sequence numbers
        for row in iter(self.proc.stdout.readline, b''):
            line_str = row.rstrip().decode("utf-8")
            self.console.debug(line_str)
            self.write_to_log(line_str)
            request = self.parse_tcpdump_line(line_str)
            connection = self.detect_established_connection(request, self.lhost, self.rhost)
            successful_exec = None
            reverse_payload_req = self.detect_reverse_payload_request(request)
            self.append_to_results(reverse_payload_req)
            dropper_req = self.detect_dropper_request(request)
            self.append_to_results(dropper_req)
            if connection is not None:
                self.console.debug("detected established connection with direction: {}".format(connection.direction))
                successful_exec = self.detect_successful_exec(connection=connection, rport=self.rport, lport=self.lport)
            if (successful_exec is not None and successful_exec != ExplExecDetectionMethod.NONE) or \
                    reverse_payload_req is not None or dropper_req is not None:
                self.append_to_results(successful_exec)
                self.console.warn("EXPLOIT HAS BEEN EXECUTED ON THE TARGET!")
                self.console.info("\t detected with: {}".format(self.results[-1].name))
                self.write_to_log("detected: ".format(self.results[-1].name))

    # Stop the subprocess
    def join(self, timeout=None):
        self.console.info("Stop capturing network traffic...")
        if self.proc is not None:
            self.console.debug("killing subprocess with PID {}...".format(self.proc.pid))
            self.proc.terminate()
            self.console.debug("killed...")
        self.file.close()
        Thread.join(self)

    # reset all connection state flags
    def reset_conn_state(self):
        self.detected_syn = False
        self.detected_synack = False
        self.syn_seq = -1
        self.synack_seq = -1

    # reset all execution state flags
    def reset_exec_state(self):
        self.detected_exploit_delivery = False
        self.detected_payload_delivery = False
        self.detected_payload_connection = False

    @staticmethod
    def remove_redundant_chars(val):
        if val[:1] == '[':
            val = val[1:]
        if val[-1:] == ':' or val[-1:] == ']':
            val = val[:-1]
        return val

    # parse a line of tcpdump and return a Request object or (in case of errors) an empty dict
    def parse_tcpdump_line(self, line):
        line = line.split(', ')
        params = []
        for item in line:
            if item[:7] == 'options':
                params.append('options')
                params.append(item[8:])
            else:
                for elem in item.split(' '):
                    params.append(elem)
        for i in range(len(params)):
            params[i] = self.remove_redundant_chars(params[i])
        if len(params) >= 7:
            request = {'time': params[0], 'protocol': params[1]}
            if request.get('protocol') == 'IP':
                request['source_ip'] = ConnectionSupervisor.extract_ip_address(params[2])
                request['source_port'] = ConnectionSupervisor.extract_port_number(params[2])
                request['target_ip'] = ConnectionSupervisor.extract_ip_address(params[4])
                request['target_port'] = ConnectionSupervisor.extract_port_number(params[4])
                request['flags'] = params[6]
                count = 7
                while count + 2 <= len(params):
                    val = params[count + 1]
                    try:
                        val = int(val)
                    except ValueError:
                        val = str(val)
                    request[params[count]] = val
                    count += 2
            return request
        return {}

    @staticmethod
    def extract_ip_address(addr_str):
        elems = addr_str.split(".")
        return "{}.{}.{}.{}".format(elems[0], elems[1], elems[2], elems[3])

    @staticmethod
    def extract_port_number(addr_str):
        try:
            return int(addr_str.split(".")[4])
        except (ValueError, IndexError):
            return -1

    # determine the direction of a given request
    def get_request_direction(self, conn, lhost, rhost):
        if lhost == conn.get('source_ip') and rhost == conn.get('target_ip'):
            return ConnectionDirection.HOST_TO_TARGET
        if lhost == conn.get('target_ip') and rhost == conn.get('source_ip'):
            return ConnectionDirection.TARGET_TO_HOST
        return ConnectionDirection.UNDETERMINED

    # returns a Connection object as soon as a successful TCP handshake has been detected
    def detect_established_connection(self, request, lhost, rhost):
        flags = request.get('flags')
        if flags == 'S':
            self.detected_syn = True
            self.syn_seq = request.get('seq')
            self.console.debug("...detected SYN")
        if flags == 'S.' and self.detected_syn and request.get('ack') == self.syn_seq + 1:
            self.detected_synack = True
            self.synack_seq = request.get('seq')
            self.console.debug("...detected SYNACK")
        if flags == '.' and self.detected_syn and self.detected_synack and request.get('ack') == self.synack_seq + 1:
            self.console.debug("...detected ACK")
            direction = self.get_request_direction(conn=request, lhost=lhost, rhost=rhost)
            self.reset_conn_state()
            self.console.debug(request)
            connection = Connection(direction=direction, client_ip=request.get('source_ip'),
                                    client_port=request.get('source_port'), server_ip=request.get('target_ip'),
                                    server_port=request.get('target_port'))
            return connection
        return None

    # detect by the given execution state and a new connection whether the exploit has already been successfully executed
    def detect_successful_exec(self, connection, rport, lport):
        self.console.debug("lport: {}, rport: {}".format(lport, rport))
        self.console.debug(connection)
        # error case
        if connection is None or connection.direction == ConnectionDirection.UNDETERMINED:
            return ExplExecDetectionMethod.NONE
        # no matter what kind of payload, the exploit needs to be delivered first
        if not self.detected_exploit_delivery and connection.direction == ConnectionDirection.HOST_TO_TARGET and connection.server_port == rport:
            self.detected_exploit_delivery = True
            self.console.info("Detected exploit delivery to target")
            return ExplExecDetectionMethod.NONE
        # to detect payload connection for single payloads:
        if not self.is_staged_payload and self.detected_exploit_delivery:
            # for single bind payloads
            if connection.direction == ConnectionDirection.HOST_TO_TARGET and not self.is_reverse_payload:  # and lport == connection.server_port
                self.console.info("Detected single bind payload connection")
                return ExplExecDetectionMethod.BIND_PAYLOAD_CONNECTION
            # for single reverse payloads
            if connection.direction == ConnectionDirection.TARGET_TO_HOST and self.is_reverse_payload and lport == connection.server_port:
                self.console.info("Detected single reverse payload connection")
                return ExplExecDetectionMethod.REVERSE_PAYLOAD_CONNECTION
        # to detect the delivery of the stage for staged payloads
        if self.is_staged_payload and self.detected_exploit_delivery and not self.detected_payload_delivery:
            if connection.direction == ConnectionDirection.TARGET_TO_HOST:
                self.detected_payload_delivery = True
                self.console.info("Reverse payload has been delivered")
                return ExplExecDetectionMethod.PAYLOAD_STAGE_CONNECTION
        # to detect the payload connection for staged payloads
        if self.detected_payload_delivery and self.is_staged_payload:
            if connection.direction == ConnectionDirection.HOST_TO_TARGET and not self.is_reverse_payload and lport == connection.server_port:
                self.console.info("Detected staged bind payload")
            if connection.direction == ConnectionDirection.TARGET_TO_HOST and self.is_reverse_payload and lport == connection.server_port:
                self.console.info("Detected staged reverse payload connection")
            return ExplExecDetectionMethod.PAYLOAD_STAGE_CONNECTION
        return ExplExecDetectionMethod.NONE

    # detect a connection attempt from a reverse payload by the given request
    def detect_reverse_payload_request(self, request):
        try:
            if self.detected_exploit_delivery and self.is_reverse_payload and request['source_ip'] == self.rhost and \
                    request['target_ip'] == self.lhost and request['target_port'] == self.lport and \
                    request.get('flags') == 'S':
                self.console.info("Detected reverse payload request.")
                return ExplExecDetectionMethod.REVERSE_PAYLOAD_REQUEST
        except KeyError:
            pass
        return None

    # detect a connection attempt from the payload's dropper
    def detect_dropper_request(self, request):
        try:
            if self.detected_exploit_delivery and self.is_staged_payload and request['source_ip'] == self.rhost and \
                    request['target_ip'] == self.lhost and not self.detected_payload_connection and \
                    request.get('flags') == 'S' and request['target_port'] != self.lport:
                self.console.info("Detected request from the payload dropper")
                return ExplExecDetectionMethod.PAYLOAD_STAGE_REQUEST
        except KeyError:
            pass
        return None

    def append_to_results(self, detection_method):
        if detection_method is not None and detection_method is not ExplExecDetectionMethod.NONE:
            self.results.append(detection_method)

    # for debugging
    def write_to_log(self, line):
        try:
            self.file.write('{} \n'.format(line))
        except ValueError:
            pass
