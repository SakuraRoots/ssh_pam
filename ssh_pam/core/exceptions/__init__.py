class SSHPAMExcepcion(Exception):
    pass


class NoGroupMappingException(SSHPAMExcepcion):
    pass

class UnableToRecordSessionException(SSHPAMExcepcion):
    pass