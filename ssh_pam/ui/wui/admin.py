from django.contrib import admin
from django.contrib.contenttypes.admin import GenericStackedInline, InlineModelAdmin

from .models import *

admin.site.register(TargetAcount)
admin.site.register(GroupMapping)
admin.site.register(HostGroup)
admin.site.register(Rule)


class AuthenticationMethodAdmin(GenericStackedInline):
    model = AuthenticationMethod
    max_num = 1

@admin.register(LDAPAuthenticationMethod)
class LDAPAuthenticationMethodAdmin(admin.ModelAdmin):
    inlines = (AuthenticationMethodAdmin,)

@admin.register(LocalFileAuthenticationMethod)
class LocalFileAuthenticationMethodAdmin(admin.ModelAdmin):
    inlines = (AuthenticationMethodAdmin,)