from ssh_pam.core.log.Logger import Logger

log = Logger.getLogger("config")

import sys

from . import validators


def list_attrs_keys(cls):
    """
    Adds a tuple KEYS with all class members

    :param cls: Class to modify
    :return: Class with KEYS tuple
    """
    import inspect

    def validator_method(k):
        return 'validate_' + k

    def set_if_validate(x, k, v):
        validater = getattr(cls, validator_method(k), lambda x: x)

        try:
            setattr(x, k, validater(v))
        except ValueError as ex:
            log.error("incorrect value for option %s. Value %s invalid: %s, Value ignored.", k, v, ex)

    cls.KEYS = tuple(
        x[0] for x in
        inspect.getmembers(cls, lambda x: not (inspect.isroutine(x)))
        if not x[0].startswith('_')
    )

    cls.set_if_validate = set_if_validate

    for k in cls.KEYS:
        val = getattr(cls, k)
        if type(val) == tuple:
            if len(val) > 1 and callable(val[1]):
                try:
                    setattr(cls, k, val[1](val[0]))
                    setattr(cls, validator_method(k), val[1])
                except ValueError as ex:
                    log.fatal("incorrect Default value for option %s. Value %s invalid. %s, EXIT.", k, val[0], ex)
                    sys.exit(-1)
            else:
                setattr(cls, k, val[0])

    return cls


@list_attrs_keys
class ConfigProxy:
    """
    Default configuration values

    """
    HOST_KEY_FILE = ('keys/ssh_host_key', validators.validate_read_file)
    BIND_ADDRESS = ('0.0.0.0', validators.validate_ip)
    BIND_PORT = (2200, validators.validate_port_number)
    SSH_BANNER = "SSH-2.0-OpenSSH"

    _SECTION = "PROXY"
    _MANDATORY = True


@list_attrs_keys
class ConfigLdap:
    """
    Default configuration values

    """
    LDAP_SERVER_URI = None
    LDAP_BIND_DN = ""
    LDAP_BIND_PASSWORD = ""
    LDAP_USER_SEARCH_BASE_DN = ""
    LDAP_USER_SEARCH_QUERY = ""

    _SECTION = "LDAP"
    _MANDATORY = False


@list_attrs_keys
class ConfigLog:
    """
    Default configuration values

    """
    LOG_FORMAT = "%(asctime)-15s [%(levelname)-7s]:%(name)-20s: %(message)s"
    LOG_LEVEL = 'INFO'
    LOG_FILE = ('logs/proxy.log', validators.validate_append_file)

    _SECTION = "LOG"
    _MANDATORY = False


class Config(ConfigProxy, ConfigLdap, ConfigLog):
    @classmethod
    def reload_config(cls):
        import os
        import configparser

        log.info('Loading configuration.')

        num_dir = len(__package__.split('.'))
        PROJECT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), *(['..'] * num_dir)))

        cfg = configparser.ConfigParser(interpolation=None)
        cfg_path = os.path.join(PROJECT_PATH, 'config', 'config.ini')

        try:
            fh = open(cfg_path)
            cfg.read_file(fh)
            fh.close()
        except OSError as ex:
            log.fatal('Unable to read from config file %s. %s', cfg_path, ex)
            sys.exit(-1)
        except configparser.Error as ex:
            log.fatal('Config file %s bad format. %s', cfg_path, ex)
            sys.exit(-1)

        for conf_cls in Config.__bases__:
            try:
                section = cfg[conf_cls._SECTION]

                for k in conf_cls.KEYS:
                    conf_cls.set_if_validate(Config, k, section.get(k, getattr(conf_cls, k)))

            except KeyError as ex:
                if conf_cls._MANDATORY:
                    log.fatal('Unable to load config section %s, not present.', conf_cls._SECTION)
                    sys.exit(-1)
                else:
                    log.info('Skip optional config section %s, not present.', conf_cls._SECTION)
