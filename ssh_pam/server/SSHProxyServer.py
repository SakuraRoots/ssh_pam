#!/usr/bin/env python

import ssh_pam

import socket
import sys
import paramiko

from binascii import hexlify
from paramiko.py3compat import u

from ssh_pam.model import LDAPAuthenticationMethod, LocalFileAuthenticationMethod
from ssh_pam.auth import LDAPAuthMethod, LocalFileAuthMethod

## CONFIG
########################
#TODO: refactor config file/db
class Config:
    LOG_FORMAT="%(asctime)-15s [%(levelname)-7s]:%(name)-20s: %(message)s"
    HOST_KEY_FILE='../private/keys/ssh_host_key'
    HTPASSWD_FILE='/home/raul/Code/ssh_pam/private/keys/users.passwd'

    BIND_ADDRESS='0.0.0.0'
    BIND_PORT=2200

conf = Config()
## Setup Logging
########################

import logging

logging.basicConfig(format=conf.LOG_FORMAT)
log = logging.getLogger("ssh-pam")
log.setLevel(logging.DEBUG)
#paramiko.util.log_to_file('demo_server.log')


class SSHProxyServer:

    def __init__(self):
        self._bind_port = conf.BIND_PORT
        self._bind_addr = conf.BIND_ADDRESS
        self._running = True

    def run(self):
        host_key = paramiko.RSAKey(filename=conf.HOST_KEY_FILE)
        log.info('Read host key: %s', u(hexlify(host_key.get_fingerprint())))

        auth_methods = self._init_auth_methods()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._bind_addr, self._bind_port))

            log.info('Listening for connection on %s:%d', conf.BIND_ADDRESS, conf.BIND_PORT)
        except Exception as e:
            log.exception('*** Bind error.')
            sys.exit(1)


        while self._running:
            try:
                sock.listen(100)
                client, addr = sock.accept()
            except Exception as e:
                log.exception('*** Listen/accept failed.')
                sys.exit(1)

            work = ssh_pam.server.SSHSession(auth_methods, client, host_key)
            work.start()

    def _init_auth_methods(self):
        for ldapAuth in LDAPAuthenticationMethod.all_enabled():
            pass




