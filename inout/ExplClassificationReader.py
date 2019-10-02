import csv

from entities.Exploit import ExploitClassification
from inout.ConsoleHandler import ConsoleHandler


class ExplClassificationReader:

    def __init__(self, db_handler):
        self.console = ConsoleHandler("ExplClassR.")
        self.db = db_handler

    def write_to_db(self, path):
        self.console.info("Start reading csv file: {}".format(path))
        try:
            with open(path) as csv_file:
                csv_reader = csv.DictReader(csv_file, delimiter=",")
                line_count = 0
                for row in csv_reader:
                    expl_class = ExploitClassification(row['Exploit'], row['Classification'])
                    self.db.add_expl_class(expl_class)
                    line_count += 1
                self.console.info("Written {} entries from Exploit Classification file to DB.".format(line_count - 1))
        except (TypeError, FileNotFoundError):
            self.console.error("Cannot open export classification file at {}.".format(path))
