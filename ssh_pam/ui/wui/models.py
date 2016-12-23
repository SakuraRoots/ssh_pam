from django.db import models
from django.core import validators
from netfields import CidrAddressField


class EnabledModel(models.Model):
    enabled = models.BooleanField(default=False)

    @staticmethod
    def all_enabled():
        return AuthenticationMethod.objects.filter(enabled=True)

    class Meta:
        abstract = True

"""
AUTHENTICATION METHODS
"""

class AuthenticationMethod(EnabledModel):
    enabled = models.BooleanField(default=False)
    name = models.CharField(max_length=128)

    def __str__(self):
        return "{}: {}".format(self.name, ('DISABLED', 'ENABLED')[self.enabled])

    @staticmethod
    def all_enabled():
        return AuthenticationMethod.objects.filter(enabled=True)


class LocalFileAuthenticationMethod(EnabledModel):
    auth = models.OneToOneField(
        AuthenticationMethod,
        on_delete=models.CASCADE,
        primary_key=True
    )
    file_path = models.CharField(max_length=255)

    def __str__(self):
        return "{} [file://{}]".format(self.auth, self.file_path)


class LDAPAuthenticationMethod(EnabledModel):
    auth = models.OneToOneField(
        AuthenticationMethod,
        on_delete=models.CASCADE,
        primary_key=True
    )
    conn_uri = models.CharField(
        max_length=255,
        validators=[validators.URLValidator(schemes=["ldaps", "ldap"])]
    )
    base_dn = models.CharField(max_length=128)
    bind_user = models.CharField(max_length=128)
    bind_passwd = models.CharField(max_length=128)

    user_class = models.CharField(max_length=128, default="inetOrgPerson")
    group_class = models.CharField(max_length=128, default="posixGroup")
    member_attr = models.CharField(max_length=128, default="memberUid")

    def __str__(self):
        return "{} [{}]".format(self.auth, self.conn_uri)


"""
RULES
"""

class HostGroup(models.Model):
    name = models.CharField(max_length=128)
    cidr = CidrAddressField()

    def __str__(self):
        return "{}: {}".format(self.name, self.cidr.exploded)

class TargetAcount(models.Model):
    name = models.CharField(max_length=128)
    username = models.CharField(max_length=128)
    passwd = models.CharField(max_length=128)

    def __str__(self):
        return "{}: {}".format(self.name, self.username)


class GroupMapping(models.Model):
    name = models.CharField(max_length=128)
    group = models.CharField(unique=True, max_length=255)
    targets = models.ManyToManyField(TargetAcount)

    def __str__(self):
        return "{}: {} - [{}]".format(
            self.name,
            self.group,
            ','.join((str(x) for x in self.targets.all()))
        )


class Rule(EnabledModel):
    name = models.CharField(max_length=128)
    hosts = models.ManyToManyField(HostGroup)
    groups = models.ManyToManyField(GroupMapping)
    preference = models.IntegerField(default=0)
    authenticator = models.ForeignKey(AuthenticationMethod)

    def __str__(self):
        return "{}: [{}] --> [{}]".format(
            self.name,
            ",".join(("<{}>".format(str(x)) for x in self.groups.all())),
            ",".join((str(x) for x in self.hosts.all()))
        )

    @staticmethod
    def get_matching_rule(target_ip, user_groups):
        if isinstance(user_groups, str):
            user_groups = [user_groups]

        return Rule.objects.filter(
            hosts__cidr__net_contains_or_equals= target_ip,
            groups__group__in= user_groups
        ).order_by('-preference').first()
