from ssh_pam.core.log import Logger

log = Logger.getLogger('auth.file')

import os

from passlib.apache import HtpasswdFile

from ssh_pam.auth import AuthenticationMethod
from ssh_pam.model import LocalFileAuthenticationMethod


class LocalFileAuthMethod(AuthenticationMethod):
    def __init__(self, options):
        """
        :type options: LocalFileAuthenticationMethod
        """
        assert options.auth.enabled

        passwd_file_path = options.file_path

        try:
            self._userdb = HtpasswdFile(passwd_file_path)
        except OSError as ex:
            log.error("Failed to open passwd file %s. %s", passwd_file_path, ex.__str__())

        AuthenticationMethod.__init__(self, "file://{}".format(os.path.abspath(passwd_file_path)))

    def authenticate(self, user, passwd):
        if not self._userdb:
            log.warning("Authentication deny. password file not opened.")
            return None
        elif user in self._userdb.users() and self._userdb.check_password(user, passwd):
            return self._allow_user(user)
        else:
            return None
