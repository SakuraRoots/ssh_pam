from ssh_pam.core.decorators import Singleton


class Logger(metaclass=Singleton):
    _LOGGER = 'ssh-pam'
    _INIT_LOG_FORMAT = "%(asctime)-15s [%(levelname)-7s]:%(name)-20s: %(message)s"
    _INIT_LOG_LEVEL = 'DEBUG'

    @classmethod
    def pre_config(cls):
        import logging
        logging.basicConfig(format=cls._INIT_LOG_FORMAT)
        log = logging.getLogger(cls._LOGGER)
        log.setLevel(logging.getLevelName(cls._INIT_LOG_LEVEL))

    @classmethod
    def init_logging(cls):
        import logging
        from ssh_pam.core.config import Config

        log = logging.getLogger(cls._LOGGER)
        logging.basicConfig(format=Config.LOG_FORMAT)
        lh = logging.FileHandler(filename=Config.LOG_FILE)
        lh.setFormatter(logging.Formatter(Config.LOG_FORMAT))
        log.addHandler(lh)
        log.setLevel(Config.LOG_LEVEL)

        log.info("Application started.")

    @staticmethod
    def getLogger(log_name=None):
        import logging

        if not log_name:
            log_name = Logger._LOGGER
        else:
            log_name = ".".join([Logger._LOGGER, log_name])

        log = logging.getLogger(log_name)

        return log
