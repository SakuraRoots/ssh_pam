from django.conf.urls import url, include
from ssh_pam.ui.wui.models import *
from rest_framework import routers, serializers, viewsets


##SERIALIZERS
#############################

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


##RULE VIEW SETS
#############################

class RuleViewSet(viewsets.ModelViewSet):
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer

class HostGroupViewSet(viewsets.ModelViewSet):
    queryset = HostGroup.objects.all()
    serializer_class = HostGroupSerializer

class TargetAccountViewSet(viewsets.ModelViewSet):
    queryset = TargetAcount.objects.all()
    serializer_class = TargetAccountSerializer


router = routers.DefaultRouter()
router.register(r'rules', RuleViewSet)
router.register(r'hosts', HostGroupViewSet)
router.register(r'target-accounts', TargetAccountViewSet)


urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework'))

]