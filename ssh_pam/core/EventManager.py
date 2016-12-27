from ssh_pam.core.log import Logger

log = Logger.getLogger('signals')

import signal

from ssh_pam.core.decorators import Singleton, static_var


class EventManager(metaclass=Singleton):
    def __init__(self):
        self._on_reload = set()
        self._on_stop = set()
        self._on_print_stats = set()

    def on_reload(self, callback):
        if not callable(callback):
            raise TypeError('callback must be a function')

        self._on_reload.add(callback)

    def on_stop(self, callback):
        if not callable(callback):
            raise TypeError('callback must be a function')

        self._on_stop.add(callback)

    def on_print_stats(self, callback):
        if not callable(callback):
            raise TypeError('callback must be a function')

        self._on_print_stats.add(callback)

    def reload(self):
        log.info('Reloading.')
        for f in self._on_reload:
            try:
                f()
            except Exception as e:
                log.exception("Unknown error on reload callback.", e)

    def stop(self):
        log.info('Stoping')
        for f in self._on_stop:
            try:
                f()
            except Exception as e:
                log.exception("Unknown error on stop callback.", e)

    def print_stats(self):
        log.info('Printing statistics.')
        for f in self._on_print_stats:
            try:
                f()
            except Exception as e:
                log.exception("Unknown error on print_stats callback.", e)


class SigHandler(metaclass=Singleton):

    event_manager = EventManager()

    @staticmethod
    def __call__(signum, frame):
        if signum == signal.SIGUSR1:
            SigHandler.event_manager.reload()
        elif signum == signal.SIGINT or signum == signal.SIGTERM:
            SigHandler.event_manager.stop()
        elif signum == signal.SIGUSR2:
            SigHandler.event_manager.print_stats()


signal.signal(signal.SIGUSR1, SigHandler())
signal.signal(signal.SIGUSR2, SigHandler())
signal.signal(signal.SIGINT, SigHandler())
signal.signal(signal.SIGTERM, SigHandler())
