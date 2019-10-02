class PayloadUtils:
    # list of preferred payloads
    # Used by metasploit internally, but listed here explicitely for the possibility to manipulate it
    # see https://metasploit.help.rapid7.com/docs/working-with-payloads
    prioritized_payloads = ['windows/meterpreter/reverse_tcp',
                            'java/meterpreter/reverse_tcp',
                            'php/meterpreter/reverse_tcp',
                            'php/meterpreter_reverse_tcp',
                            'ruby/shell_reverse_tcp',
                            'cmd/unix/interact',
                            'cmd/unix/reverse',
                            'cmd/unix/reverse_perl',
                            'cmd/unix/reverse_netcat_gaping',
                            'windows/meterpreter/reverse_nonx_tcp',
                            'windows/meterpreter/reverse_ord_tcp',
                            'windows/shell/reverse_tcp',
                            'generic/shell_reverse_tcp']

    @staticmethod
    def get_prioritized_payload(payloads):
        for payload in PayloadUtils.prioritized_payloads:
            if payload in payloads:
                return payload
        return payloads[0]

    @staticmethod
    def is_reverse_payload(payload):
        return 'reverse' in payload.modulename

    @staticmethod
    def is_staged_payload(payload):
        if 'singles' in payload.filepath:
            return False
        if 'stage' in payload.filepath:
            return True
        raise LookupError("Cannot determine type of payload for '{}'".format(payload.modulename))
