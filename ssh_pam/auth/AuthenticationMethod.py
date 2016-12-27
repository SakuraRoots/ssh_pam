from ssh_pam.core.log import Logger

log = Logger.getLogger('auth')

from abc import ABCMeta, abstractmethod

from ssh_pam.model import User


class AuthenticationMethod(metaclass=ABCMeta):
    def __init__(self, realm):
        self.realm = realm
        log.info("Authentication method realm %s loaded.", self.realm)

    @abstractmethod
    def authenticate(self, user, passwd):
        pass

    def _allow_user(self, username, groups=[]):
        return User(username, self.realm, groups)
