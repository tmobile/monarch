"""
A general purpose singleton metaclass.
"""


class Singleton(type):
    """
    Basic singleton type
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Override the type 'call'.  If no _instance, or if _instance is
        empty then raise error.  Handler instantiates the object.  We
        check for the existence of the variable to facilitate teardown
        during testing.
        """
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]
