from setuptools import setup

setup(
    name='ssh_pam',
    version='0.2',
    packages=['ssh_pam'],
    url='https://github.com/rsrdesarrollo/ssh_pam',
    license='AGPLv3',
    author='rsrdesarrollo',
    author_email='rsrdesarrollo@gmail.com',
    description='',
    requires=[
        'paramiko==2.0.2', 'ldap3', 'passlib',
        'hvac', 'django', 'django-netfields',
        'djangorestframework', 'djangorestframework-jwt', 'markdown',
        'django-filter', 'psycopg2'
    ]
)
