"""
A single application instance which is hosted on a garden container which is on a diego cell.
"""

import monarch.util as util


class AppInstance(dict):
    """
    A single instance of an application. Contains information about where it is hosted and the ports it is bound to.

    diego_id: str; ID string of the Diego Cell which hosts this app instance.
    diego_ip: str; IP of the Diego Cell which hosts this app instance.
    diego_vi: str; Name of the virtual network interface on the diego cell for this application instance.
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

    def run_cmd_on_diego_cell(self, cmd):
        """
        Run a command in the shell on the hosting diego cell.
        :param cmd: str; Command to run on the Diego Cell.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return util.run_cmd_on_diego_cell(self['diego_id'], cmd)

    def run_cmd_on_container(self, cmd):
        """
        Run a command in the shell on the hosting diego cell.
        :param cmd: str; Command to run on the container.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return util.run_cmd_on_container(self['diego_id'], self['cont_id'], cmd)
