from ssh_pam.core.log import Logger

log = Logger.getLogger('record')

from abc import ABCMeta, abstractmethod

import select

from paramiko.py3compat import u
from ssh_pam.core.exceptions import UnableToRecordSessionException
from ssh_pam.core.status import SSHSessionStatus


class SSHSessionRecorder(metaclass=ABCMeta):
    def __init__(self, session):
        """
        :param session:
        :type session: ssh_pam.server.SSHSession.SSHSession
        """
        self.session = session

    @abstractmethod
    def record_server_message(self, buffer):
        pass

    @abstractmethod
    def record_client_message(self, buffer):
        pass

    @abstractmethod
    def close_recorder(self):
        pass

    def record_loop(self, cli_channel, srv_channel):

        try:
            while self.session.status != SSHSessionStatus.SESSION_CLOSED:
                r, _, _ = select.select([cli_channel, srv_channel], [], [])

                if cli_channel in r:
                    x = u(cli_channel.recv(1024))
                    if len(x) == 0:
                        srv_channel.close()
                        break

                    self.record_client_message(x)

                    srv_channel.send(x)

                if srv_channel in r:
                    x = u(srv_channel.recv(1024))
                    if len(x) == 0:
                        cli_channel.close()
                        break

                    self.record_server_message(x)

                    cli_channel.send(x)

        except UnableToRecordSessionException as ex:
            log.error('unable to record session. %s', ex)
            cli_channel.send("unable to audit.\n\r")
        finally:
            self.close_recorder()