import time

import pymongo
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from config import db_config
from entities.ExecStatus import ExecStatus
from entities.Exploit import Exploit, ExploitClass
from entities.Vulnerability import Vulnerability
from inout.ConsoleHandler import ConsoleHandler


class DBHandler:
    def __init__(self, msf_handler):
        self.msf_handler = msf_handler
        self.console = ConsoleHandler("DBHandler")
        self.exploits = []
        self.db_client = MongoClient(db_config.get("host"), db_config.get("port"))
        self.db = self.db_client.pyperpwn
        self.expl_coll = self.db.exploits
        self.cve_coll = self.db.cve
        self.vuln_coll = self.db.vulns
        self.expl_class_coll = self.db.classifications
        self.exec_status_coll = self.db.exec_status
        self.check_db_connection()

    def check_db_connection(self):
        self.console.info("Checking connection to MongoDB...")
        try:
            self.db_client.server_info()
        except ServerSelectionTimeoutError:
            self.console.error(
                "Unable to connect to MongoDB! Please check if it is running and reachable on {}:{}. Aborting...".format(
                    db_config.get("host"), db_config.get("port")))
            raise ConnectionError('cannot connect to MongoDB.')

    # remove all cached data that is not necessary for a clean start
    def clear_db_on_start(self):
        self.console.debug("Remove cached data from DB...")
        self.db.vulns.remove({})
        self.db.exec_status_coll.remove({})

    # remove all data that has been cached in the DB
    def remove_cached_data(self):
        self.expl_class_coll.remove({})

    # checks if a refill of the exploit collection is necessary and if yes, performs it
    def build_expl_coll(self):
        self.console.info("Checking state of Exploit Cache...")
        if self.check_db():
            self.console.info("\t No need to fill cache again. Proceeding...")
            return
        self.console.info("\t Remove orphaned exploits...")
        self.expl_coll.delete_many({})
        self.console.info("\t Start caching exploits...")
        fail_count = 0
        i = 0
        for expl_name in self.msf_handler.get_all_exploits():
            expl = self.get_exploit_obj_by_name(expl_name)
            if expl is None:
                fail_count += 1
            else:
                self.expl_coll.insert_one(expl)
            i += 1
        self.expl_coll.create_index([('search_name', pymongo.TEXT)], name='search_index', default_language='english')
        self.console.info(
            "Successfully built cache with {} entries. Faced {} errors".format(i - fail_count, fail_count))

    # creates an exploit object from the MSF data related to the given exploit path
    def get_exploit_obj_by_name(self, expl_path):
        expl = self.msf_handler.get_exploit(expl_path)
        cve = DBHandler.get_module_attribute('CVE', expl.references)
        bid = DBHandler.get_module_attribute('BID', expl.references)
        full_name = expl._info['name']
        search_name = Exploit.improve_name(full_name)
        rank = expl._info['rank']
        os = DBHandler.get_os_from_expl_name(expl_path)
        expl_obj = Exploit(path=expl_path, full_name=full_name, search_name=search_name, os=os, rank=rank, cve=cve,
                           bid=bid, all_params=expl.options, req_params=expl.required, score=0.0)
        expl_dict = expl_obj.to_dict()
        return expl_dict

    # check if the DB contains almost the same amount of exploits as MSF
    def check_db(self):
        db_count = self.expl_coll.count_documents({})
        msf_count = len(self.msf_handler.get_all_exploits())
        self.console.info(
            "\t Found {} exploits in DB, while MSF currently offers {} in total".format(db_count, msf_count))
        if db_count + db_config.get("diff_range") >= msf_count:
            return True
        return False

    @staticmethod
    def get_module_attribute(tag, attribute_list):
        for elem in attribute_list:
            if elem[0] == tag:
                return elem[1]
        return ""

    @staticmethod
    def get_os_from_expl_name(expl_name):
        expl_name = expl_name.split("/")
        return expl_name[0]

    def search_by_cve(self, cve):
        matching_expl = []
        for expl in self.expl_coll.find({"cve": cve}):
            expl_obj = Exploit.from_dict(expl)
            matching_expl.append(expl_obj)
        return matching_expl

    def search_by_bid(self, bid):
        matching_expl = []
        for expl in self.expl_coll.find({"bid": bid}):
            expl_obj = Exploit.from_dict(expl)
            matching_expl.append(expl_obj)
        return matching_expl

    # search the DB for all exploits with a matching name (textScore)
    def search_by_name(self, name):
        matching_expl = []
        for expl in self.expl_coll.find({'$text': {'$search': name}}, {'score': {'$meta': 'textScore'}}):
            expl_obj = Exploit.from_dict(expl)
            matching_expl.append(expl_obj)
        return matching_expl

    #
    # methods for the CVE details collection
    #
    def add_cve_details(self, cve):
        self.cve_coll.insert_one(cve)

    def get_cve(self, cve):
        return self.cve_coll.find_one({'cve': cve})

    #
    # methods for the exploits' classifications collection
    #
    def add_expl_class(self, expl_class):
        self.expl_class_coll.insert_one(expl_class.to_dict())

    def get_expl_class(self, expl_path):
        classification_obj = self.expl_class_coll.find_one({'expl_path': expl_path})
        if classification_obj is None:
            return None
        return getattr(ExploitClass, classification_obj.get('class', None).upper(), None)

    #
    # methods for application's execution status
    #
    def save_exec_status(self, status):
        status.ended = time.time()
        self.exec_status_coll.insert_one(status.to_dict())
        self.console.info("Successfully saved execution status to DB...")

    def take_matching_exec_status(self, ip):
        status_dict = self.exec_status_coll.find_one({'ip': ip})
        if status_dict is None:
            return None
        self.exec_status_coll.delete_one({'_id': status_dict.get('_id')})
        return ExecStatus.from_dict(status_dict)

    #
    # methods for vulnerabilities collection
    #
    def save_vulns(self, vulns):
        for vuln in vulns:
            self.vuln_coll.insert_one(vuln.to_dict())

    def get_vulns(self):
        vuln_objs = []
        vulns = self.vuln_coll.find({}).sort('cvss', pymongo.DESCENDING)
        for vuln in vulns:
            vuln_obj = Vulnerability.from_dict(vuln)
            vuln_objs.append(vuln_obj)
        return vuln_objs
