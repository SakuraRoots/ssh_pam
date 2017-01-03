from ssh_pam.core.config import Config
from ssh_pam.core.log import Logger

log = Logger.getLogger()

import socketserver

from binascii import hexlify

import paramiko
from paramiko.py3compat import u

from ssh_pam.auth import LDAPAuthMethod, LocalFileAuthMethod
from ssh_pam.model import LDAPAuthenticationMethod, LocalFileAuthenticationMethod, AuthenticationMethod
from ssh_pam.server import SSHSession


class SSHProxyServer(socketserver.ThreadingTCPServer):
    def __init__(self):
        server_address = (Config.BIND_ADDRESS, Config.BIND_PORT)
        socketserver.ThreadingTCPServer.__init__(self, server_address, SSHSession)

        self.host_key = paramiko.RSAKey(filename=Config.HOST_KEY_FILE)
        self.auth_methods = self._init_auth_methods()

        log.info('Read host key: %s', u(hexlify(self.host_key.get_fingerprint())))

    def _init_auth_methods(self):
        auth_methods = dict()
        for ldapAuth in AuthenticationMethod.all_enabled_type(LDAPAuthenticationMethod):
            auth_methods[ldapAuth.pk] = LDAPAuthMethod(ldapAuth.content_object)

        for fileAuth in AuthenticationMethod.all_enabled_type(LocalFileAuthenticationMethod):
            auth_methods[fileAuth.pk] = LocalFileAuthMethod(fileAuth.content_object)

        return auth_methods
