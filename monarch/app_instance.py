"""
A single application instance which is hosted on a garden container which is on a diego cell.
"""


class AppInstance(dict):
    """
    A single instance of an application. Contains information about where it is hosted and the ports it is bound to.

    diego_id: str; ID string of the Diego Cell which hosts this app instance.
    diego_ip: str; IP of the Diego Cell which hosts this app instance.
    cont_id: str; GUID of the Garden Container which hosts this app instance.
    cont_ip: str; IP of the Garden Container which hosts this app instance.
    app_ports: set[(int, int)]; Ports the application instance is bound to (DiegoPort, ContainerPort).
    """

    def serialize(self):
        """
        Convert this application instance into a serializable dictionary.
        :return: Serializable dictionary representation of the app instance.
        """
        obj = self.copy()
        obj['app_ports'] = [p for p in self['app_ports']]
        return obj
