from ssh_pam.core.log import Logger

log = Logger.getLogger('session')

import select
import socket
import threading

import paramiko
from paramiko.py3compat import u

from ssh_pam.core.exceptions import *
from ssh_pam.model import Rule
from ssh_pam.core.config import Config
from ssh_pam.core import EventManager

from enum import Enum, unique

def run_statistics(func):
    def decorator(self, *args, **kwargs):
        try:
            decorator._runing.add(self)
            func(self, *args, **kwargs)
            decorator._runing.remove(self)
        except:
            raise

    decorator._runing = set()

    return decorator

@unique
class SSHSessionStatus(Enum):
    CONNECTION_OPEN=1
    AUTH_PENDING=2
    CHANNEL_OPEN=3
    SESSION_OPEN=4

class SSHSession(paramiko.ServerInterface, threading.Thread):
    """
    :type _server_channel: paramiko.channel.Channel
    :type rule: Rule
    """

    def __init__(self, auth_methods, socket, host_key):
        """
        :type auth_methods: dict(ssh_auditor.authn.AuthenticationMethod.AuthenticationMethod)
        :type socket: socket.socket
        :type host_key: paramiko.RSAKey
        """
        threading.Thread.__init__(self)

        self.daemon = True
        self.target_server = None
        self.username = None
        self.user = None
        self.rule = None

        self._status = SSHSessionStatus.CONNECTION_OPEN
        self._event_session_open = threading.Event()

        self._server_conn = None
        self._server_channel = None

        self._client_channel = None
        self._client_addr = socket.getpeername()[0]

        self._host_key = host_key
        self._auth_methods = auth_methods
        self._socket = socket
        self._running = True

        EventManager().on_stop(self.stop)

    def __str__(self):
        return "user: {} -> ({})@{}\t STATUS:{}".format(
            self.username,
            self.user,
            self.target_server,
            self.status
        )

    @property
    def status(self):
        return self._status.name

    def _load_tranport(self):
        transport = paramiko.Transport(self._socket)
        transport.local_version = Config.SSH_BANNER

        try:
            transport.load_server_moduli()
        except:
            log.warning('Failed to load moduli. group-exchange key negotiation will not be suported')

        transport.add_server_key(self._host_key)

        try:
            transport.start_server(server=self)
        except paramiko.SSHException as ex:
            log.error('SSH negotiation failed for client %s. %s', self._client_addr, ex)

            try:
                transport.close()
            except Exception:
                pass

            return None

        self._status = SSHSessionStatus.AUTH_PENDING
        return transport.accept()

    def stop(self):
        self._running = False
        try:
            self._client_channel.send("\n\rBye! closing channel from remote host\n\r")
            self._client_channel.close()
            self._server_channel.close()
        except:
            pass

    @run_statistics
    def run(self):
        chan = self._load_tranport()
        if chan is None:
            log.error('No channel oppened for user %s from %s.', self.username, self._client_addr)
            return
        self._status = SSHSessionStatus.CHANNEL_OPEN

        self._event_session_open.wait(10)
        if not self._event_session_open.is_set():
            log.error('Client %s never asked for a pty.', self.user)
            return

        self._status = SSHSessionStatus.SESSION_OPEN

        srv = self._server_channel
        cli = self._client_channel

        while self._running:
            r, _, _ = select.select([cli, srv], [], [])

            if cli in r:
                x = u(cli.recv(1024))
                if len(x) == 0:
                    srv.close()
                    break

                srv.send(x)

            if srv in r:
                x = u(srv.recv(1024))
                if len(x) == 0:
                    cli.close()
                    break

                cli.send(x)

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        :type username: str
        :type password: str
        """
        try:
            self.username = username.split("@")[0]
            self.target_server = socket.gethostbyname(username.split("@")[1])

            self.rule = Rule.get_matching_rule(self.target_server)

            if self.rule:
                self.user = self._auth_methods[self.rule.authenticator_id].authenticate(
                    self.username,
                    password
                )

                if self.user:
                    log.info("auth_successful %s from %s", self.user, self._socket.getpeername()[0])
                    return paramiko.AUTH_SUCCESSFUL

            log.info("auth_failed %s from %s", username, self._socket.getpeername()[0])

        except IndexError:
            log.info("auth_failed %s from %s. Is double ssh chain present?", username, self._socket.getpeername()[0])
        except Exception as ex:
            log.exception("auth_failed %s from %s. unknown exception", username, self._socket.getpeername()[0], ex)

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """
        :type channel: paramiko.channel.Channel
        """
        target_user = None

        try:
            target_user, target_passwd, target_port = self.rule.get_target_credentials(
                self.user.groups,
                self.target_server
            )

            self._server_conn = paramiko.SSHClient()
            self._server_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._server_conn.connect(self.target_server, target_port, target_user, target_passwd)
            self._server_channel = self._server_conn.invoke_shell(term, width, height, pixelwidth, pixelheight)
            self._client_channel = channel

            self._event_session_open.set()
            return True

        except paramiko.AuthenticationException as ex:
            log.error("Client %s failed to authenticate on second tranche to %s@%s",
                      self.user,
                      target_user,
                      self.target_server
                      )
            channel.close()

        except paramiko.BadHostKeyException as ex:
            log.error("%s", ex)

        except paramiko.SSHException:
            log.error("Client %s failed to create shell on second tranche to %s@%s",
                      self.user,
                      target_user,
                      self.target_server
                      )
        except NoGroupMappingException:
            log.info("Client %s failed to connect to %s. No group mapping",
                     self.user,
                     self.target_server
                     )

        channel.send("failed connection to target server\n")
        channel.close()
        return False

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        try:
            self._server_channel.resize_pty(width, height, pixelwidth, pixelheight)
        except paramiko.SSHException:
            return False

        return True

    def check_port_forward_request(self, address, port):
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    @staticmethod
    def print_stadistics():
        log.info("STADISTICS: connections: %d", len(SSHSession.run._runing))

        for conn in SSHSession.run._runing:
            log.info("STADISTICS: session %s", conn)


EventManager().on_print_stats(SSHSession.print_stadistics)