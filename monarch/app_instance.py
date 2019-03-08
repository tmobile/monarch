"""
A single application instance which is hosted on a garden container which is on a diego cell.
"""
from logzero import logger

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
        :param cmd: Union[str, List[str]]; Command(s) to run on the Diego Cell.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return util.run_cmd_on_diego_cell(self['diego_id'], cmd)

    def run_cmd_on_container(self, cmd):
        """
        Run a command in the shell on the hosting diego cell.
        :param cmd: Union[str, List[str]]; Command(s) to run on the container.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return util.run_cmd_on_container(self['diego_id'], self['cont_id'], cmd)

    def perform_speedtest(self, server=None):
        """
        Perform a speedtest check from within the container.

        :return: obj; Example:
        ```
        {
          "client": {
            "rating": "0",
            "loggedin": "0",
            "isprating": "3.7",
            "ispdlavg": "0",
            "ip": "208.54.104.5",
            "isp": "T-Mobile USA",
            "lon": "-97.822",
            "ispulavg": "0",
            "country": "US",
            "lat": "37.751"
          },
          "bytes_sent": 142606336,
          "download": 1845278668.1228614,  # bits per second
          "timestamp": "2019-03-08T21:42:22.873445Z",
          "share": null,
          "bytes_received": 409373932,
          "ping": 12.161,  # miliseconds
          "upload": 202308479.3912031,  # bits per second
          "server": {
            "latency": 12.161,
            "name": "Wichita, KS",
            "url": "http://speedtest.rd.ks.cox.net/speedtest/upload.php",
            "country": "United States",
            "lon": "-97.3372",
            "cc": "US",
            "host": "speedtest.rd.ks.cox.net:8080",
            "sponsor": "Cox - Wichita",
            "lat": "37.6922",
            "id": "16623",
            "d": 43.13860244182284
          }
        }
        ```
        """
        _, stdout, _ = self.run_cmd_on_container([
            'cd /tmp',
            'wget https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py',
            'python speedtest.py --json {}'.format('' if not server else '--server ' + server),
            'rm speedtest.py'
        ])
        results = util.extract_json(stdout)
        if not results:
            logger.error("Failed to perform speedtest on %s!", self['cont_id'])
            return None
        return results[0]
