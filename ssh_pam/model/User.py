class User:

    def __init__(self, username, realm, groups=[]):
        self.username = username
        self.groups = groups
        self.realm = realm

    def __str__(self):
        return "{} [{}]".format(self.username, self.realm)