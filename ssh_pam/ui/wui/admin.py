from django.contrib import admin
from django.contrib.contenttypes.admin import GenericStackedInline, InlineModelAdmin
from django import forms

from .models import *

admin.site.register(GroupMapping)
admin.site.register(HostGroup)
admin.site.register(Rule)

class TargetAccountAdminForm(forms.ModelForm):
    passwd = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = TargetAcount
        fields = ('name', 'username', 'passwd')

@admin.register(TargetAcount)
class TargetAccountAdmin(admin.ModelAdmin):
    form = TargetAccountAdminForm

class AuthenticationMethodAdmin(GenericStackedInline):
    model = AuthenticationMethod
    max_num = 1

@admin.register(LDAPAuthenticationMethod)
class LDAPAuthenticationMethodAdmin(admin.ModelAdmin):
    inlines = (AuthenticationMethodAdmin,)

@admin.register(LocalFileAuthenticationMethod)
class LocalFileAuthenticationMethodAdmin(admin.ModelAdmin):
    inlines = (AuthenticationMethodAdmin,)