#!/usr/bin/env python

import os
from subprocess import Popen, PIPE

PROJECT="pamssh"

SSH="{}_ssh_1".format(PROJECT)
LDAP="{}_ldap_1".format(PROJECT)
PS="{}_postgres_1".format(PROJECT)
LDAP_ADMIN="{}_ldap-admin_1".format(PROJECT)


def get_ip_container(container):
    return Popen(
        ["docker", "inspect", "--format", "'{{ .NetworkSettings.IPAddress }}'", container],
        stdout=PIPE,
        universal_newlines=True
    ).communicate()[0].strip().strip("'")

## LDAP
os.environ["LDAP_USER"]="cn=admin,dc=example,dc=org"
os.environ["LDAP_PASSWD"]="admin"
os.environ["LDAP_BASEDN"]="dc=example,dc=org"

## postgres
os.environ["DB_PORT"]=""
os.environ["DB_USER"]="root"
os.environ["DB_PASSWD"]="toor"
os.environ["DB_DATABASE"]="devel"

def start_environment():
    p = Popen(
        ['docker-compose', '-p', PROJECT, 'up', '-d'],
        cwd=os.path.join(os.path.dirname(__file__), 'docker')
    )

    p.wait()

    os.environ["LDAP_URL"]="ldap://{}:389".format(get_ip_container(LDAP))
    os.environ["DB_HOST"]=get_ip_container(PS)

    print("postgres: runing on",os.environ["DB_HOST"])
    print("ldap: runing on", os.environ["LDAP_URL"])
    print("phpldap admin: runing on https://{}".format(get_ip_container(LDAP_ADMIN)))


def stop_environment():
    p = Popen(
        ['docker-compose', '-p', PROJECT, 'down'],
        cwd=os.path.join(os.path.dirname(__file__), 'docker')
    )

if __name__ == '__main__':
    start_environment()