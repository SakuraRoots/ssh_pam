from ssh_pam.model import User
from abc import ABCMeta, abstractmethod

import logging
log = logging.getLogger("ssh-pam.auth")

class AuthenticationMethod(metaclass=ABCMeta):

    def __init__(self, realm):
        self.realm = realm
        log.info("Authentication method realm %s loaded.", self.realm)

    @abstractmethod
    def authenticate(self,user,passwd):
        raise NotImplementedError()

    def _allow_user(self, username, groups=[]):
        return User(username, self.realm, groups)