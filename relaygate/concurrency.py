from functools import wraps
import threading


def serialize_services(services):
    """One reentrant lock covers complete operations sharing a SQLite connection.

    Callers using raw app['db'] must hold app['lock'] after startup. The HTTP
    handler holds it for entire requests, including its direct SQL queries.
    """
    lock = threading.RLock()

    def wrap(method):
        @wraps(method)
        def synchronized(*args, **kwargs):
            with lock:
                return method(*args, **kwargs)
        return synchronized

    for service in services:
        if hasattr(service, "_lock"):
            service._lock = lock
        for name in dir(type(service)):
            if not name.startswith("_"):
                method = getattr(service, name)
                if callable(method):
                    setattr(service, name, wrap(method))
    return lock
