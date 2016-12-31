from rest_framework import serializers

from ssh_pam.ui.wui.models import *

class RuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rule
        fields = ('id', 'name', 'preference', 'enabled', 'authenticator', 'hosts', 'groups')


class HostGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostGroup
        fields = ('id', 'name', 'cidr', 'port')


class TargetAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetAcount
        fields = ('id', 'name', 'username')