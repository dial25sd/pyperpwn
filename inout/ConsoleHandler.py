import time

from config import Colours, log_config
from inout.Logger import Logger


class ConsoleHandler:

    def __init__(self, name):
        self.name = name
        self.show_debug = log_config.get('debug')
        self.logger = Logger(self.name)

    def info(self, text):
        self.logger.info(text)
        print("{}{} {:12}{} [{}+{}] {}".format(Colours.background, time.strftime('%X'), self.name, Colours.end,
                                               Colours.info, Colours.end, text))

    def prompt(self, text):
        answer = input(
            "{}{} {:12}{} [{}?{}] {}: ".format(Colours.background, time.strftime('%X'), self.name, Colours.end,
                                               Colours.prompt, Colours.end, text))
        self.logger.info("Prompted for {}, received input: {}".format(text, answer))
        return answer

    def error(self, text):
        self.logger.error(text)
        print("{}{} {:12}{} [{}X{}] {}".format(Colours.background, time.strftime('%X'), self.name, Colours.end,
                                               Colours.error, Colours.end, text))

    def warn(self, text):
        self.logger.warn(text)
        print(
            "{}{} {:12}{} [{}!{}] {}".format(Colours.background, time.strftime('%X'), self.name, Colours.end,
                                             Colours.warn, Colours.end, text))

    def debug(self, text):
        self.logger.debug(text)
        if self.show_debug:
            print("{}{} {:12}{} [{}i{}] {}".format(Colours.background, time.strftime('%X'), self.name, Colours.end,
                                                   Colours.debug, Colours.end, text))

    def empty(self, count):
        for i in range(count):
            print("")

    def caption(self, text):
        self.logger.info(text)
        print(text)
