import os

from django.test import TestCase

from ssh_pam.auth import LDAPAuthMethod
from ssh_pam.ui.wui.models import LDAPAuthenticationMethod, AuthenticationMethod


class TestLDAPAuthMethod(TestCase):
    def setUp(self):
        import tests.init_env

        tests.init_env.start_environment()

        self.LDAP_URL = os.environ['LDAP_URL']
        self.LDAP_USER = os.environ['LDAP_USER']
        self.LDAP_PASSWD = os.environ['LDAP_PASSWD']
        self.LDAP_BASEDN = os.environ['LDAP_BASEDN']

        auth = AuthenticationMethod.objects.create(name='test ldap', enabled=True)
        self.ldapAuth = LDAPAuthenticationMethod.objects.create(
            auth=auth,
            conn_uri=self.LDAP_URL,
            base_dn=self.LDAP_BASEDN,
            bind_user=self.LDAP_USER,
            bind_passwd=self.LDAP_PASSWD
        )

    def test_authenticate_failure_false_user(self):
        auth = LDAPAuthMethod(self.ldapAuth)
        user = auth.authenticate(
            'notauseradsfpikkjadspfoihkbj',
            'not.a.password'
        )

        self.assertIsNone(user, "Authentication successful for invalid user")

    def test_authenticate_failure_false_passwd(self):
        auth = LDAPAuthMethod(self.ldapAuth)
        user = auth.authenticate(
            'home2',
            'not.a.password'
        )

        self.assertIsNone(user, "Authentication successful with invalid password")

    def test_authenticate_successful(self):
        auth = LDAPAuthMethod(self.ldapAuth)
        user = auth.authenticate(
            'home2',
            'home2'
        )

        self.assertIsNotNone(user, "Authentication failed for valid user")
