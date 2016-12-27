from ssh_pam.core.log import Logger

log = Logger.getLogger("auth.ldap")

import ldap3
from ldap3.core.exceptions import *

from ssh_pam.auth import AuthenticationMethod
from ssh_pam.model import LDAPAuthenticationMethod


class LDAPAuthMethod(AuthenticationMethod):
    def __init__(self, options):
        """
        :type options: LDAPAuthenticationMethod
        """
        self._op = options
        self._enabled = options.auth.enabled

        try:
            conn = ldap3.Connection(
                options.conn_uri,
                options.bind_user,
                options.bind_passwd,
                auto_bind=True
            )
            conn.unbind()

        except LDAPException as ex:
            log.exception("connecting LDAP backend", ex)

        AuthenticationMethod.__init__(self, options.conn_uri)

    def authenticate(self, user, passwd):
        if not self._enabled:
            log.error("authentication request for disabled authentication backend")
            return None

        try:
            conn = ldap3.Connection(
                ldap3.Server(self._op.conn_uri),
                self._op.bind_user,
                self._op.bind_passwd,
                auto_bind=True
            )

            user_dn = self._find_user_dn(user, conn)

            if user_dn and conn.rebind(user_dn, passwd):
                conn.rebind(self._op.bind_user, self._op.bind_passwd)

                groups = self._find_user_groups(user, conn)

                return self._allow_user(user, groups)

        except LDAPBindError:
            pass
        except LDAPException as ex:
            log.exception("unknown error authenticating user", ex)
        finally:
            try:
                conn.unbind()
            except:
                pass

        return None

    def _find_user_dn(self, user, conn):
        assert self._enabled

        res = conn.search(
            self._op.base_dn,
            '(& (objectClass={}) (cn={}))'.format(
                self._op.user_class,
                user
            )
        )

        if res:
            return conn.entries[0].entry_dn
        else:
            return None

    def _find_user_groups(self, user, conn):
        """
        :param user: Username
        :type user: str
        :param conn: LDAP Connection object
        :type conn: ldap3.Connection

        :return: List of groups (str)
        :rtype: list
        """
        assert self._enabled

        res = conn.search(
            self._op.base_dn,
            '(& (objectClass={}) ({}={}))'.format(
                self._op.group_class,
                self._op.member_attr,
                user
            )
        )

        if res:
            return [x.entry_dn for x in conn.entries]
        else:
            return []
