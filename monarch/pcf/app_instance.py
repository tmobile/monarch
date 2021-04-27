# Copyright 2019 T-Mobile US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" A single application instance which is hosted on a garden container which is on a diego cell.
"""
from itertools import chain

from logzero import logger

import monarch.pcf.util
import monarch.util as util
from monarch.pcf import TIMES_TO_REMOVE
from monarch.pcf.config import Config


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

    def run_cmd_on_diego_cell(self, cmd, **kwargs):
        """
        Run a command in the shell on the hosting diego cell.
        :param cmd: Union[str, List[str]]; Command(s) to run on the Diego Cell.
        :param kwargs: Additional arguments to pass to run_cmd_on_diego_cell.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return monarch.pcf.util.run_cmd_on_diego_cell(self['diego_id'], cmd, **kwargs)

    def run_cmd_on_container(self, cmd, **kwargs):
        """
        Run a command in the shell on the hosting diego cell.
        :param cmd: Union[str, List[str]]; Command(s) to run on the container.
        :param kwargs: Additional arguments to pass to run_cmd_on_container.
        :return: int, str, str; Returncode, stdout, stderr.
        """
        return monarch.pcf.util.run_cmd_on_container(self['diego_id'], self['cont_id'], cmd, **kwargs)

    def crash(self):
        """
        Crash this application instance.
        :return: int; A returncode if the operation failed.
        """
        logger.info('Crashing app instance at %s with container %s:%s.',
                    self['diego_id'], self['cont_ip'], self['cont_id'])
        rcode, _, _ = self.run_cmd_on_container('pkill -SIGSEGV java')

        if rcode:
            logger.error("Failed to crash application container %s:%s.",
                         self['cont_id'], self['cont_ip'])
            return rcode
        return 0

    def block(self, direction='ingress', ports='env'):
        """
        Block access to this application instance on all its known hosts.
        :param direction: str; Traffic direction to block.
        :param ports: Union[str, set[int]]; Which ports to block, either 'env', 'all', or a custom list/set. If 'env', it
        will read from the environment to determine what port to block, this is the default and will work for most apps.
        Use 'all' if you want to block all traffic to and or from the application. Specify a custom list to only block
        certain ports; IF A CUSTOM LIST IS SPECIFIED, it must also be passed to unblocking.
        :return: Union[int, List[str]]; A returncode if any of the bosh ssh instances do not return 0 and a list of
        commands that would have been run if `get_cmds` is True.
        """
        direction = util.parse_direction(direction)
        assert direction, "Could not parse direction!"

        cmds = []
        if ports == 'all':
            logger.info("Targeting %s on %s", self['diego_id'], self['cont_ip'])
            if direction in {'ingress', 'both'}:
                cmds.append('sudo iptables -I FORWARD 1 -d {} -p tcp -j DROP'.format(self['cont_ip']))
            if direction in {'egress', 'both'}:
                cmds.append('sudo iptables -I FORWARD 1 -s {} -p tcp -j DROP'.format(self['cont_ip']))
            if not cmds:
                return 0  # noop
        else:
            if ports == 'env':
                ports = map(lambda v: v[1], filter(self._app_port_not_whitelisted, self['app_ports']))
            else:
                assert isinstance(ports, set) or isinstance(ports, list), 'Ports argument is invalid'
            for cport in ports:
                logger.info("Targeting %s on %s:%d", self['diego_id'], self['cont_ip'], cport)

                if direction in {'ingress', 'both'}:
                    cmds.append('sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP'
                                .format(self['cont_ip'], cport))
                if direction in {'egress', 'both'}:
                    cmds.append('sudo iptables -I FORWARD 1 -s {} -p tcp --sport {} -j DROP'
                                .format(self['cont_ip'], cport))
            if not cmds:
                return 0  # noop

        rcode, _, _ = self.run_cmd_on_diego_cell(cmds)
        if rcode:
            logger.error("Received return code %d from iptables call.", rcode)
            return rcode
        return 0

    def unblock(self, ports=None):
        """
        Unblock access to this application instance on all its known hosts. This will actually run the unblock commands
        multiple times, as defined by `TIMES_TO_REMOVE` to prevent issues if an application was blocked multiple times.
        :param ports: set[int]; List of custom ports to unblock.
        """
        cmds = []
        logger.info("Unblocking %s on %s", self['diego_id'], self['cont_ip'])
        cmd = 'sudo iptables -D FORWARD -d {} -p tcp -j DROP'.format(self['cont_ip'])
        for _ in range(TIMES_TO_REMOVE):
            cmds.append(cmd)
        cmd = 'sudo iptables -D FORWARD -s {} -p tcp -j DROP'.format(self['cont_ip'])
        for _ in range(TIMES_TO_REMOVE):
            cmds.append(cmd)

        ports = chain(
            map(
                lambda v: v[1],
                filter(self._app_port_not_whitelisted, self['app_ports'])
            ), (ports or [])
        )
        for cport in ports:
            logger.info("Unblocking %s on %s:%d", self['diego_id'], self['cont_ip'], cport)
            cmd = 'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP'.format(self['cont_ip'], cport)
            for _ in range(TIMES_TO_REMOVE):
                cmds.append(cmd)
            cmd = 'sudo iptables -D FORWARD -s {} -p tcp --sport {} -j DROP'.format(self['cont_ip'], cport)
            for _ in range(TIMES_TO_REMOVE):
                cmds.append(cmd)

        self.run_cmd_on_diego_cell(cmds, suppress_output=True)

    def manipulate_network(self, *, latency=None, latency_sd=None, loss=None, loss_r=None,
                           duplication=None, corruption=None, rate=None, direction='egress'):
        """
        Manipulate the network traffic from the application instance and its services. This will not work simultaneously
        with network shaping, but the network shaping behavior can also be achieved via the rate parameter of this
        method.

        :param latency: int; Latency to introduce in milliseconds.
        :param latency_sd: int; Standard deviation of the latency in milliseconds, if None, there will be no variance.
        With relatively large variance values, packet reordering will occur.
        :param loss: float; Percent in the range [0, 1] of packets which should be dropped/lost.
        :param loss_r: float; Correlation coefficient in the range [0, 1] of the packet loss.
        :param duplication: float; Percent in the range [0, 1] of packets which should be duplicated.
        :param corruption: float; Percent in the range [0, 1] of packets which should be corrupted.
        :param direction: str; Traffic direction to manipulate.
        :param rate: Throughput rate limiting in kbps. See `rate` in https://man7.org/linux/man-pages/man8/tc-netem.8.html
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        if not (latency or loss or duplication or corruption or rate):
            # if no actions are specified, it is a noop
            return 0

        direction = util.parse_direction(direction)
        assert direction, "Could not parse direction!"

        setup_cmds = []
        netem_cmds = []
        iface = self['diego_vi']

        # For notes regarding applying netem to ingress traffic see:
        #   https://wiki.linuxfoundation.org/networking/netem#how_can_i_use_netem_on_incoming_traffic3f

        if direction in {'ingress', 'both'}:
            # NOTE: ifb module will be left as loaded. this seems harmless enough and is simpler than trying to
            #     determine if we are the ones who loaded it. likewise with the ifb0 ip link being left in the up state
            # N.B.: if changes are made to the filter command for some reason, then corresponding changes may be
            #     needed in the `unmanipulate_network` method since the del command used their is quite specific.
            setup_cmds.extend([
                'sudo modprobe ifb',
                'sudo ip link set dev ifb0 up',
                f'sudo tc qdisc add dev {iface} ingress',
                f'sudo tc filter add dev {iface} parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0'
            ])
            netem_cmds.append(['sudo', 'tc', 'qdisc', 'add', 'dev', 'ifb0', 'root', 'netem'])

        if direction in {'egress', 'both'}:
            netem_cmds.append(['sudo', 'tc', 'qdisc', 'add', 'dev', iface, 'root', 'netem'])

        for netem_cmd in netem_cmds:
            if latency:
                assert latency > 0
                netem_cmd.extend(['delay', '{}ms'.format(latency)])
                if latency_sd:
                    assert latency_sd > 0
                    netem_cmd.extend(['{}ms'.format(latency_sd), 'distribution', 'normal'])
            if loss:
                assert 0 <= loss <= 1
                netem_cmd.extend(['loss', '{}%'.format(loss * 100)])
                if loss_r:
                    assert 0 <= loss_r <= 1
                    netem_cmd.append('{}%'.format(loss_r * 100))
            if duplication:
                assert 0 <= duplication <= 1
                netem_cmd.extend(['duplicate', '{}%'.format(duplication * 100)])
            if corruption:
                assert 0 <= corruption <= 1
                netem_cmd.extend(['corrupt', '{}%'.format(corruption * 100)])
            if rate:
                assert rate > 0
                netem_cmd.extend(['rate', f'{rate}kbit'])

        if len(setup_cmds) > 0:
            self.run_cmd_on_diego_cell(setup_cmds, suppress_output=True)

        for netem_cmd in netem_cmds:
            rcode, _, _ = self.run_cmd_on_diego_cell(' '.join(netem_cmd))
            if rcode:
                logger.error("Failed to manipulate network for app instance with rcode %d!", rcode)
                self.unmanipulate_network()
                return rcode

        return 0

    def shape_network(self, download_limit=None, upload_limit=None):
        """
        TODO: recommend deprecating this method. The new `rate` param in manipulate_network functionally replaces it,
            and this seems appropriate based on the following note from https://man7.org/linux/man-pages/man8/tc-netem.8.html...
            "rate - delay packets based on packet size and is a replacement for TBF." TBF is what shape_network
            utilizes.

        Impose bandwidth limits on the application's ingress traffic. This will not work simultaneously with other
        network traffic manipulations and will also be undone by calling `unmanipulate_network`.

        TODO: improve upload limiting, right now it is using a policing policy instead of a queuing policy.

        See also https://lartc.org/howto/lartc.cookbook.ultimate-tc.html.
        See also https://github.com/magnific0/wondershaper/.

        :param download_limit: The maximum download speed in kilobits per second.
        :param upload_limit: The maximum upload speed in kilobits per second. NOTE: If enabled, it will cap out at
        around 8Mbps.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        if not (download_limit or upload_limit):
            return 0  # noop

        def burst_size(bandwidth):
            """
            Based on specification that for 10Mbps, it requires a 10kbyte buffer.
            See https://linux.die.net/man/8/tc-tbf.
            :param bandwidth: Desired bandwith limit in Kbps.
            :return: The recommended burst size.
            """
            mbps = bandwidth / 1000
            buff_in_kbyte = mbps
            buff_in_bytes = buff_in_kbyte * 1024
            return max(int(buff_in_bytes), 100)

        iface = self['diego_vi']
        cmds = []

        if download_limit:
            # Limit container download by limiting the virtual interface's egress traffic
            cmds.append('sudo tc qdisc add dev {} root tbf rate {}kbit latency {}ms burst {}'
                        .format(iface, download_limit, 50, burst_size(download_limit)))
        if upload_limit:
            # Limit container upload by limiting the virtual interface's ingress traffic
            cmds.extend([
                'sudo tc qdisc add dev {} handle ffff: ingress'.format(iface),
                'sudo tc filter add dev {} parent ffff: protocol ip prio 1 u32 match ip src '
                '0.0.0.0/0 police rate {}kbit burst {} drop flowid :1'
                .format(iface, upload_limit, burst_size(upload_limit))
            ])

        rcode, _, _ = self.run_cmd_on_diego_cell(cmds)
        if rcode:
            logger.error('Failed to limit bandwidth, received error code %d.', rcode)
            self.unmanipulate_network()
            return rcode
        return 0

    def unmanipulate_network(self):
        """
        Undo traffic manipulation changes to the application and its services.
        """
        # https://serverfault.com/a/488914/648174 (and the link given there)
        # By just deleting the root/ingress devices, it will reset everything else.
        iface = self['diego_vi']
        self.run_cmd_on_diego_cell([
            f'sudo tc qdisc del dev {iface} root',
            f'sudo tc qdisc del dev {iface} ingress',
            'sudo tc qdisc del dev ifb0 root',
        ], suppress_output=True)

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
        # res = requests.get('https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py')
        # if not res:
        #     return None
        _, stdout, _ = self.run_cmd_on_container([
            'cd /tmp',
            # 'echo "{}" > speedtest.py'.format(res.text.replace('\n', '\\n')),
            'wget https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py',
            'python speedtest.py --json {}'.format('' if not server else '--server ' + server),
            'rm speedtest.py'
        ])
        results = util.extract_json(stdout)
        if not results:
            logger.error("Failed to perform speedtest on %s!", self['cont_id'])
            return None
        return results[0]

    @staticmethod
    def _app_port_not_whitelisted(ports):
        cfg = Config()
        return ports[0] not in cfg['host-port-whitelist'] and \
               ports[1] not in cfg['container-port-whitelist']
