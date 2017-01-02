def validate_directory(dirname):
    import os
    num_dir = len(__package__.split('.'))
    PROJECT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), *(['..'] * num_dir)))

    if not os.path.isabs(dirname):
        dirname = os.path.join(PROJECT_PATH, dirname)

    dirname = os.path.normpath(dirname)

    return dirname

def validate_permissions_file(file_path, perm):
    import os
    num_dir = len(__package__.split('.'))
    PROJECT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), *(['..'] * num_dir)))
    try:
        if not os.path.isabs(file_path):
            file_path = os.path.join(PROJECT_PATH, file_path)

        file_path = os.path.normpath(file_path)
        fh = open(file_path, perm)
        fh.close()
    except:
        raise ValueError('can not read from file')

    return file_path


def validate_read_file(file_path):
    return validate_permissions_file(file_path, 'r')


def validate_append_file(file_path):
    return validate_permissions_file(file_path, 'a')


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


def validate_log_level(level):
    import logging
    level = logging.getLevelName(level)
    if type(level) != int:
        raise ValueError('{} is not a valid log level', format(level))

    return level
