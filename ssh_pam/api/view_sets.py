from rest_framework import viewsets
from .serializers import *

class RuleViewSet(viewsets.ModelViewSet):
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer


class HostGroupViewSet(viewsets.ModelViewSet):
    queryset = HostGroup.objects.all()
    serializer_class = HostGroupSerializer


class TargetAccountViewSet(viewsets.ModelViewSet):
    queryset = TargetAcount.objects.all()
    serializer_class = TargetAccountSerializer
