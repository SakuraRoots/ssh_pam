import os
import logging
import inspect
import configparser
import sys

log = logging.getLogger("ssh-pam.config")

SECTION="PROXY"

PROJECT_PATH = os.path.join(os.path.dirname(__file__), '..', '..')


def list_attrs_keys(cls):
    """
    Adds a tuple KEYS with all class members

    :param cls: Class to modify
    :return: Class with KEYS tuple
    """
    def validator_method(k):
        return 'validate_'+k

    def set_if_validate(k, v):
        validater = getattr(cls, validator_method(k), lambda x: x)

        try:
            setattr(cls, k, validater(v))
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



def validate_read_file(file_path):
    try:
        file_path = os.path.normpath(file_path)
        fh = open(file_path)
        fh.close()
    except:
        raise ValueError('can not read from file')

    return file_path

def validate_ip(address):
    import socket
    address = address.strip()
    try:
        socket.inet_pton(socket.AF_INET, address)
    except:
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except:
            raise ValueError('not a valid IPv4 nor IPv6')

    return address

def validate_port_number(integer):
    if type(integer) != int:
        try:
            integer = int(integer)
        except:
            raise ValueError('not a valid integer')


    if integer <= 0 or integer > 0xffff:
        raise ValueError('not a valid port number')

    return integer

@list_attrs_keys
class Default:
    """
    Default configuration values

    """
    LOG_FORMAT="%(asctime)-15s [%(levelname)-7s]:%(name)-20s: %(message)s"
    HOST_KEY_FILE=(os.path.join(PROJECT_PATH, 'keys/ssh_host_key'), validate_read_file)
    BIND_ADDRESS=('0.0.0.0', validate_ip)
    BIND_PORT=(2200, validate_port_number)
    SSH_BANNER="SSH-2.0-OpenSSH"



class Config(Default):

    @classmethod
    def reload_config(cls):

        cfg = configparser.ConfigParser(interpolation=None)

        cfg_path = os.path.join(PROJECT_PATH, 'config', 'config.ini')

        try:
            cfg.read(cfg_path)
            section = cfg[SECTION]

            for k in Config.KEYS:
                Config.set_if_validate(k, section.get(k, getattr(Default,k)))

        except OSError as ex:
            pass
        except configparser.Error as ex:
            pass

        pass



