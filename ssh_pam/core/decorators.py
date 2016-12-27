import functools


def singleton(cls):
    cls.__old_new__ = cls.__new__

    @functools.wraps(cls.__new__)
    def singleton_new(cls, *args, **kargs):
        inst = cls.__dict__.get('_inst')

        if inst is not None:
            return inst

        cls._inst = inst = cls.__old_new__(cls, *args, **kargs)
        inst.__old_init__(*args, **kargs)

        return inst

    cls.__new__ = singleton_new
    cls.__old_init__ = cls.__init__
    cls.__init__ = object.__init__

    return cls


def static_var(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func

    return decorate


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
