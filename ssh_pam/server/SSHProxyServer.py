#!/usr/bin/env python

import socket
import sys
from binascii import hexlify

import paramiko
from paramiko.py3compat import u

import ssh_pam
from ssh_pam.auth import LDAPAuthMethod, LocalFileAuthMethod
from ssh_pam.model import LDAPAuthenticationMethod, LocalFileAuthenticationMethod



from ssh_pam.config import Config

import logging

logging.basicConfig(format=Config.LOG_FORMAT)
log = logging.getLogger("ssh-pam")
log.setLevel(logging.DEBUG)


# paramiko.util.log_to_file('demo_server.log')


class SSHProxyServer:
    def __init__(self):
        self._bind_port = Config.BIND_PORT
        self._bind_addr = Config.BIND_ADDRESS
        self._running = True

    def run(self):
        host_key = paramiko.RSAKey(filename=Config.HOST_KEY_FILE)
        log.info('Read host key: %s', u(hexlify(host_key.get_fingerprint())))

        auth_methods = self._init_auth_methods()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._bind_addr, self._bind_port))

            log.info('Listening for connection on %s:%d', Config.BIND_ADDRESS, Config.BIND_PORT)
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
        auth_methods = dict()
        for ldapAuth in LDAPAuthenticationMethod.all_enabled():
            auth_methods[ldapAuth.auth.pk] = LDAPAuthMethod(ldapAuth)

        for fileAuth in LocalFileAuthenticationMethod.all_enabled():
            auth_methods[fileAuth.auth.pk] = LocalFileAuthMethod(fileAuth)

        return auth_methods
