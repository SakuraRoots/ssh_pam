from django.contrib import admin

from .models import *

admin.site.register(TargetAcount)
admin.site.register(GroupMapping)
admin.site.register(HostGroup)
admin.site.register(Rule)

admin.site.register(AuthenticationMethod)
admin.site.register(LDAPAuthenticationMethod)
admin.site.register(LocalFileAuthenticationMethod)