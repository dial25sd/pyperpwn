import csv
import datetime

from entities.ReportEntry import ReportEntry
from inout.ConsoleHandler import ConsoleHandler


class CSVWriter:

    def __init__(self):
        self.console = ConsoleHandler("CSVWriter")

    def write_csv(self, path, report_entries):
        for entry in report_entries:
            entry.timestamp = datetime.datetime.fromtimestamp(float(entry.timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        self.console.debug("Start writing csv file: {}".format(path))
        count = 0
        with open(path, mode='w') as report:
            fieldnames = ReportEntry.get_field_names()
            column_titles = ReportEntry.get_column_names()
            report_writer = csv.DictWriter(report, delimiter=",", fieldnames=fieldnames)
            report_writer.writerow(dict(zip(fieldnames, column_titles)))
            for entry in report_entries:
                report_writer.writerow(entry.to_dict())
                count += 1
        self.console.debug("Wrote {} lines to the report file.".format(count))
        self.console.info("You can find the generated report at '{}'.".format(path))
