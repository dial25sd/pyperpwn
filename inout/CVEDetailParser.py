import re

import requests

from config import cve_details_config
from inout.ConsoleHandler import ConsoleHandler

CVE_PATTERN = "CVE-\d{4}-\d{4,7}"
CVE_TYPE_PARSER_PATTERN = '<th>Vulnerability Type\(s\)</th>(\s)*<td>(\s)*<span class="(\w)*">((\w)*( (\w)*)+)</span>'
CVE_TYPE_GROUP_ID_IN_PATTERN = 4


class CVEDetailParser:

    def __init__(self, db_handler):
        self.console = ConsoleHandler("CVEDetParser")
        self.db = db_handler

    def get_cve_details(self, cves):
        if cves == "NOCVE":
            return None
        cves = CVEDetailParser.parse_cves(self.console, cves)
        vuln_types = []
        for cve in cves:
            cve_from_db = self.db.get_cve(cve)
            if cve_from_db is None:
                html = self.retrieve_cve_details(cve)
                vuln_type = self.parse_cve_type(html)
                if vuln_type is not None:
                    self.console.debug("\t successfully extracted vulnerability type for {}: {}".format(cve, vuln_type))
                    vuln_types.append(vuln_type)
                    self.db.add_cve_details({'cve': cve, 'type': vuln_type})
                else:
                    self.console.error("\t Unable to extract Vulnerability type for {}".format(cve))
            else:
                vuln_types.append(cve_from_db['type'])
                self.console.debug("received CVE type from DB: {} {}".format(cve_from_db['cve'], cve_from_db['type']))
        if len(vuln_types) == 0:
            return None
        vuln_type = list(set(vuln_types))
        self.console.debug("\t extracted vuln type: {}".format(vuln_type))
        return vuln_type

    def retrieve_cve_details(self, cve):
        path = cve_details_config.get("url") + cve
        try:
            r = requests.get(path, timeout=20)
            if r.status_code != requests.codes.ok:
                self.console.error("\t unable to retrieve CVE details.")
            return r.text
        except requests.exceptions.ConnectionError:
            self.console.error("Cannot retrieve CVE details. Please check your internet connection.")
            return ""

    def parse_cve_type(self, html):
        match = re.search(CVE_TYPE_PARSER_PATTERN, html)
        if match is None:
            return None
        return match.group(CVE_TYPE_GROUP_ID_IN_PATTERN)

    # parses single CVE-ID from a string with several CVE-IDs separated by a comma
    @staticmethod
    def parse_cves(console, cve):
        parsed_cves = []
        cves = cve.split(",")
        for i, _ in enumerate(cves):
            cves[i] = cves[i].strip()
        for cve in cves:
            match = re.match(CVE_PATTERN, cve)
            if match is not None:
                parsed_cves.append(cve)
        remove_count = len(cves) - len(parsed_cves)
        if remove_count > 0:
            console.debug("removed {} CVE entries because of a non-matching format".format(remove_count))
        return parsed_cves

    # parse a list of BIDs
    @staticmethod
    def parse_bids(bid_str):
        parsed_bids = []
        bids = bid_str.split(",")
        for bid in bids:
            bid = bid.strip()
            parsed_bids.append(bid)
        return parsed_bids
