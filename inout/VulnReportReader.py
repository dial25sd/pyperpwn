import csv

from entities.Vulnerability import Vulnerability
from inout.ConsoleHandler import ConsoleHandler


class VulnReportReader:

    def __init__(self):
        self.console = ConsoleHandler("VulnReader")

    # read the vuln report from a CSV file and return a list of Vulnerability objects
    def read_csv(self, path):
        self.console.info("Start reading csv file: {}".format(path))
        entries = []
        try:
            with open(path) as csv_file:
                csv_reader = csv.DictReader(csv_file, delimiter=",")
                line_count = 0
                for row in csv_reader:
                    port = -1
                    cvss = -1.0
                    try:
                        try:
                            port = int(row['Port'])
                        except ValueError:
                            self.console.warn(
                                "\t Cannot convert 'Port' value from vuln report at line {}".format(line_count))
                        try:
                            cvss = float(row['CVSS'])
                        except ValueError:
                            self.console.warn(
                                "\t cannot convert 'CVSS' value from vuln report at line {}".format(line_count))
                        vuln = Vulnerability(row['IP'], port=port, cvss=cvss, protocol=row['Protocol'],
                                             cve=row['CVEs'], bid=row['BIDs'], name=row['Name'],
                                             detection=row['Detection Method'], solution_type   =row['Solution Type'])
                        entries.append(vuln)
                        line_count += 1
                    except KeyError as e:
                        self.console.error("\t Cannot read column from report file: {}".format(e))
                        raise KeyError
            self.console.info("Read {} entries from Vulnerability Scanner Output".format(line_count))
            return entries
        except (TypeError, FileNotFoundError):
            self.console.error("Cannot read report file. Aborting...")
            raise FileNotFoundError
