from ssh_pam.core.log import Logger

log = Logger.getLogger('session')

import socket
import socketserver
import threading

import paramiko

from ssh_pam.core import EventManager
from ssh_pam.core.config import Config
from ssh_pam.core.exceptions import *
from ssh_pam.core.status import SSHSessionStatus

from ssh_pam.model import Rule
from ssh_pam.server.recorders import FileSSHSessionRecorder


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





class SSHSession(paramiko.ServerInterface, socketserver.BaseRequestHandler):
    """
    :type _server_channel: paramiko.channel.Channel
    :type rule: Rule
    """

    def setup(self):
        """
        :type auth_methods: dict(ssh_auditor.authn.AuthenticationMethod.AuthenticationMethod)
        :type socket: socket.socket
        :type host_key: paramiko.RSAKey
        """
        self.target_server = None
        self.target_user = None
        self.target_port = None

        self.username = None
        self.user = None
        self.rule = None

        self.status = SSHSessionStatus.CONNECTION_OPEN
        self._event_session_open = threading.Event()

        self._transport = None
        self._server_conn = None
        self._server_channel = None
        self._client_channel = None

        EventManager().on_stop(self.stop)

    def __str__(self):
        return "user: {} -> ({})@{}\t STATUS:{}".format(
            self.username,
            self.user,
            self.target_server,
            self.status.name
        )

    def _load_tranport(self):
        transport = paramiko.Transport(self.request)
        transport.local_version = Config.SSH_BANNER

        try:
            transport.load_server_moduli()
        except:
            log.warning('Failed to load moduli. group-exchange key negotiation will not be suported')

        transport.add_server_key(self.server.host_key)

        try:
            transport.start_server(server=self)
        except paramiko.SSHException as ex:
            log.error('SSH negotiation failed for client %s. %s', self.client_address, ex)

            try:
                transport.close()
            except Exception:
                pass

            return None

        self.status = SSHSessionStatus.AUTH_PENDING
        self._transport = transport

        return transport.accept()

    def stop(self):
        self.status = SSHSessionStatus.SESSION_CLOSED
        try:
            self._client_channel.send("\n\rBye! closing channel from remote host\n\r")
        except:
            pass

        try:
            self._server_channel.send("\x03\x04")
        except:
            pass

    @run_statistics
    def handle(self):
        chan = self._load_tranport()
        if chan is None:
            log.error('No channel oppened for user %s from %s.', self.username, self.client_address)
            return
        self.status = SSHSessionStatus.CHANNEL_OPEN

        self._event_session_open.wait(10)
        if not self._event_session_open.is_set():
            log.error('Client %s never asked for a pty.', self.user)
            return

        self.status = SSHSessionStatus.SESSION_OPEN
        recorder = FileSSHSessionRecorder(self)

        recorder.record_loop(
            srv_channel=self._server_channel,
            cli_channel=self._client_channel
        )


    def finish(self):
        if self._transport:
            self._transport.close()

        if self._server_conn:
            self._server_conn.close()

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
                self.user = self.server.auth_methods[self.rule.authenticator_id].authenticate(
                    self.username,
                    password
                )

                if self.user:
                    log.info("auth_successful %s from %s", self.user, self.request.getpeername()[0])
                    return paramiko.AUTH_SUCCESSFUL

            log.info("auth_failed %s from %s", username, self.request.getpeername()[0])

        except IndexError:
            log.info("auth_failed %s from %s. Is double ssh chain present?", username, self.request.getpeername()[0])
        except Exception as ex:
            log.exception("auth_failed %s from %s. unknown exception", username, self.request.getpeername()[0], ex)

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """
        :type channel: paramiko.channel.Channel
        """
        try:
            self.target_user, target_passwd, self.target_port = self.rule.get_target_credentials(
                self.user.groups,
                self.target_server
            )

            self._server_conn = paramiko.SSHClient()
            self._server_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._server_conn.connect(self.target_server, self.target_port, self.target_user, target_passwd)
            self._server_channel = self._server_conn.invoke_shell(term, width, height, pixelwidth, pixelheight)
            self._client_channel = channel

            self._event_session_open.set()
            return True

        except paramiko.AuthenticationException as ex:
            log.error("Client %s failed to authenticate on second tranche to %s@%s",
                      self.user,
                      self.target_user,
                      self.target_server
                      )

        except paramiko.BadHostKeyException as ex:
            log.error("%s", ex)

        except paramiko.SSHException:
            log.error("Client %s failed to create shell on second tranche to %s@%s",
                      self.user,
                      self.target_user,
                      self.target_server
                      )
        except NoGroupMappingException:
            log.info("Client %s failed to connect to %s. No group mapping",
                     self.user,
                     self.target_server
                     )

        channel.send("failed connection to target server\n")
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
