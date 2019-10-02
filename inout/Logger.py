import logging


class Logger:

    def __init__(self, name):
        self.name = name
        self.logger = self.setup_custom_logger(name)

    def setup_custom_logger(self, name):
        formatter = logging.Formatter(fmt='%(asctime)s %(name)-16s %(levelname)-8s %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        handler = logging.FileHandler('pyperpwn_log.txt', mode='a')
        handler.setFormatter(formatter)
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        return logger

    def info(self, text):
        self.logger.info(text)

    def warn(self, text):
        self.logger.warning(text)

    def error(self, text):
        self.logger.error(text)

    def debug(self, text):
        self.logger.debug(text)
