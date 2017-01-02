from ssh_pam.core.log import Logger

log = Logger.getLogger('record.file')

from ssh_pam.core.config import Config
from ssh_pam.core.exceptions import UnableToRecordSessionException

from .SSHSessionRecorder import SSHSessionRecorder
from os import path, makedirs
from datetime import datetime

import re

ANSI_ESCAPE = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', re.IGNORECASE)

class FileSSHSessionRecorder(SSHSessionRecorder):
    def __init__(self, session):
        """
        :param session:
        :type session: ssh_pam.server.SSHSession.SSHSession
        """

        SSHSessionRecorder.__init__(self, session)

        file_path = path.join(Config.FILE_RECORD_PATH, Config.FILE_RECORD_NAME).format(
            user=re.sub('[^0-9a-zA-Z.\[\]]+', '_', str(session.user)),
            date=datetime.now().strftime("%Y.%m.%d"),
            datetime=datetime.now().strftime("%Y.%m.%d_%H%M%S.%f"),
            target_ip=session.target_server,
            target_user=session.target_user,
            target_port=session.target_port
        )

        try:
            makedirs(path.dirname(file_path), exist_ok=True)

            self._file = None
            self._file = open(file_path, mode='w')

            log.debug("file loggin open on %s", file_path)

        except OSError as ex:
            log.error('error starting file recorder on file %s. %s. Session will be terminated.', file_path, ex)

    def _record_message(self, buff):
        if not self._file:
            raise UnableToRecordSessionException('record file not opened')

        self._file.write(ANSI_ESCAPE.sub('', buff))

    def record_server_message(self, buff):
        self._record_message(buff)

    def record_client_message(self, buff):
        pass # Recorded by SSH Echo from server

    def close_recorder(self):
        if self._file:
            try:
                self._file.close()
            except:
                pass
