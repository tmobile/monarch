"""
Cloud foundry Application tools.
"""

import json
import re
import sys
from random import shuffle

from logzero import logger

from monarch import TIMES_TO_REMOVE
from monarch.app_instance import AppInstance
from monarch.config import Config
from monarch.service import Service
import monarch.util as util


class App:
    """
    Information about an application and all of the locations it is hosted.
    """

    @staticmethod
    def discover(org, space, appname):
        """
        Find an application's hosts and services and return the findings as an application object.
        :param org: String; the cloud foundry organization the application is hosted in.
        :param space: String; the cloud foundry organization space the application is hosted in.
        :param appname: String; the name of the application deployment within cloud foundry.
        :return: App; Instance of App which holds all the discovered information.
        """
        if util.cf_target(org, space):
            logger.error("Failed to target org %s and space %s!", org, space)
            return None
        app = App(org, space, appname)
        if app.find_guid() and app.find_instances() and app.find_services():
            logger.debug(json.dumps(app.serialize(), indent=2))
            return app
        return None

    def __init__(self, org, space, appname):
        """
        Initialize a new hosted app object. See also discover_app.
        :param org: String; the cloud foundry organization the application is hosted in.
        :param space: String; the cloud foundry organization space the application is hosted in.
        :param appname: String; the name of the application deployment within cloud foundry.
        """
        self.org = org
        self.space = space
        self.name = appname
        self.guid = None
        self.services = []
        self.instances = []

    def __len__(self):
        """
        Find how many instances of this app there are
        :return: int; The application instances.
        """
        return len(self.instances)

    def __hash__(self):
        """
        Calculate a unique identifier for this application based on its organization, space, and application name.
        :return: A unique identifier for this application.
        """
        return hash(self.get_id())

    def __repr__(self):
        return 'App({})'.format(self.get_id())

    def serialize(self):
        """
        Convert this application instance into a serializable dictionary.
        :return: Serializable dictionary representation of the app.
        """
        return {
            'org': self.org,
            'space': self.space,
            'name': self.name,
            'guid': self.guid,
            'services': [s.serialize() for s in self.services],
            'instances': [i.serialize() for i in self.instances]
        }

    def get_id(self):
        """
        Create a unique descriptor for this application. It will take the form 'org_space_appname'.
        :return: String; A unique descriptor for this application.
        """
        return '_'.join([self.org, self.space, self.name])

    def find_guid(self):
        """
        Find the GUID of an application using cloud foundry's CLI interface. The GUID acts as a unique identifier for
        the application which we can then use to find what containers are running it.
        :return: String; The application GUID.
        """
        self.guid = find_application_guid(self.name)
        return self.guid

    def find_instances(self):
        """
        Find the containers which host an application by using cfdot.
        :return: Dict[String, DiegoHost]; The diego-cells which host this app and their associated sub-containers.
        """
        self.instances = find_application_instances(self.guid)
        return self.instances

    def find_services(self):
        """
        Discover all services bound to this application. This will use `cf env` and parse the output for VCAP_SERVICES.
        :return: Dict[String, Service]; The list of all services bound to this application.
        """
        self.services = find_application_services(self.name)
        return self.services

    def crash_random_instance(self, count=1):
        """
        Crash one or more random application instances.
        :param count: int; Number of instances to crash.
        """
        instances = self.instances.copy()
        count = min(count, len(instances))
        shuffle(instances)
        instances = instances[:count]

        for app_instance in instances:
            logger.info('Crashing app instance at %s with container %s:%s.',
                        app_instance['diego_id'], app_instance['cont_ip'], app_instance['cont_id'])
            cmd = "sudo /var/vcap/packages/runc/bin/runc exec {} /usr/bin/pkill -SIGSEGV java"\
                .format(app_instance['cont_id'])
            rcode, _, _ = util.run_cmd_on_diego_cell(app_instance['diego_id'], cmd)

            if rcode:
                logger.error("Failed to crash application container %s:%s.",
                             app_instance['cont_id'], app_instance['cont_ip'])

    def block(self):
        """
        Block access to this application on all its known hosts.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        for app_instance in self.instances:
            cmds = []

            for _, cport in filter(self._app_port_not_whitelisted, app_instance['app_ports']):
                logger.info("Targeting %s on %s:%d", app_instance['diego_id'], app_instance['cont_ip'], cport)
                cmds.append('sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP'
                            .format(app_instance['cont_ip'], cport))
            if not cmds:
                continue

            rcode, _, _ = util.run_cmd_on_diego_cell(app_instance['diego_id'], '\n'.join(cmds))

            if rcode:
                logger.error("Received return code %d from iptables call.", rcode)
                self.unblock()
                return rcode
        return 0

    def unblock(self):
        """
        Unblock access to this application on all its known hosts. This will actually run the unblock commands multiple
        times, as defined by `TIMES_TO_REMOVE` to prevent issues if an application was blocked multiple times.
        """
        for app_instance in self.instances:
            cmds = []

            for _, cport in filter(self._app_port_not_whitelisted, app_instance['app_ports']):
                logger.info("Unblocking %s on %s:%d", app_instance['diego_id'], app_instance['cont_ip'], cport)
                cmd = 'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP'.format(app_instance['cont_ip'], cport)
                for _ in range(TIMES_TO_REMOVE):
                    cmds.append(cmd)
            if not cmds:
                continue

            util.run_cmd_on_diego_cell(app_instance['diego_id'], '\n'.join(cmds))

    def block_services(self, services=None):
        """
        Block this application from accessing its services on all its known hosts.
        :param services: List[String]; List of service names to block, will target all if unset.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        cfg = Config()
        for app_instance in self.instances:
            cmds = []
            for service in self.services:
                if service['type'] in cfg['service-whitelist']:
                    continue
                if services and service['name'] not in services:
                    continue
                logger.info("Blocking %s for %s:%s", service['name'], app_instance['diego_id'], app_instance['cont_ip'])
                for (sip, protocol, port) in service['hosts']:
                    cmd = 'sudo iptables -I FORWARD 1 -s {} -d {} -p {}'.format(app_instance['cont_ip'], sip, protocol)
                    if port != 'all':
                        cmd += ' --dport {}'.format(port)
                    cmd += ' -j DROP'
                    cmds.append(cmd)
            if not cmds:
                continue
            rcode, _, _ = util.run_cmd_on_diego_cell(app_instance['diego_id'], '\n'.join(cmds))
            if rcode:
                logger.error("Received return code %d from iptables call.", rcode)
                self.unblock_services(services=services)
                return rcode
        return 0

    def unblock_services(self, services=None):
        """
        Unblock this application from accessing its services on all its known hosts.
        :param services: List[String]; List of service names to unblock, will target all if unset.
        """
        cfg = Config()
        for app_instance in self.instances:
            cmds = []
            for service in self.services:
                if service['type'] in cfg['service-whitelist']:
                    continue
                if services and service['name'] not in services:
                    continue
                logger.info("Blocking %s for %s:%s", service['name'], app_instance['diego_id'], app_instance['cont_ip'])
                for (sip, protocol, port) in service['hosts']:
                    cmd = 'sudo iptables -D FORWARD -s {} -d {} -p {}'.format(app_instance['cont_ip'], sip, protocol)
                    if port != 'all':
                        cmd += ' --dport {}'.format(port)
                    cmd += ' -j DROP'
                    for _ in range(TIMES_TO_REMOVE):
                        cmds.append(cmd)
            if not cmds:
                continue
            util.run_cmd_on_diego_cell(app_instance['diego_id'], '\n'.join(cmds))
            # if rcode:
            #     # This is normal because we remove the rule more than one time just in case.
            #     logger.warn("Received return code {} from iptables call.".format(rcode))
            #     code = rcode

    def manipulate_network(self, *, latency=None, latency_sd=None, loss=None, loss_r=None,
                           duplication=None, corruption=None):
        """
        Manipulate the network traffic to the application and its services. This will not work simultaneously with
        network shaping.

        :param latency: int; Latency to introduce in milliseconds.
        :param latency_sd: int; Standard deviation of the latency in milliseconds, if None, there will be no variance.
        With relatively large variance values, packet reordering will occur.
        :param loss: float; Percent in the range [0, 1] of packets which should be dropped/lost.
        :param loss_r: float; Correlation coefficient in the range [0, 1] of the packet loss.
        :param duplication: float; Percent in the range [0, 1] of packets which should be duplicated.
        :param corruption: float; Percent in the range [0, 1] of packets which should be corrupted.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        if not (latency or loss or duplication or corruption):
            # if no actions are specified, it is a noop
            return 0

        for app_instance in self.instances:
            cmd = ['sudo', 'tc', 'qdisc', 'add', 'dev', app_instance['diego_vi'], 'root netem']
            if latency:
                assert latency > 0
                cmd.extend(['delay', '{}ms'.format(latency)])
                if latency_sd:
                    assert latency_sd > 0
                    cmd.extend(['{}ms'.format(latency_sd), 'distribution', 'normal'])
            if loss:
                assert 0 <= loss <= 1
                cmd.extend(['loss', '{}%'.format(loss * 100)])
                if loss_r:
                    assert 0 <= loss_r <= 1
                    cmd.append('{}%'.format(loss_r * 100))
            if duplication:
                assert 0 <= duplication <= 1
                cmd.extend(['duplicate', '{}%'.format(duplication * 100)])
            if corruption:
                assert 0 <= corruption <= 1
                cmd.extend(['corrupt', '{}%'.format(corruption * 100)])
            rcode, _, _ = util.run_cmd_on_diego_cell(app_instance['diego_id'], ' '.join(cmd))
            if rcode:
                logger.error("Failed to manipulate network for app instance with rcode %d!", rcode)
                self.unmanipulate_network()
                return rcode
        return 0

    def shape_network(self, upload_speed):
        """
        Impose bandwidth limits on the application. This will not work simultaneously with other network traffic
        manipulations and will also be undone by calling `unmanipulate_network`.

        Code ported from https://github.com/magnific0/wondershaper/.

        :param upload_speed: The maximum upload speed in kilobits per second. (Must be >=10)
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        assert upload_speed >= 10
        cfg = Config()

        for app_instance in self.instances:
            iface = app_instance['diego_vi']
            cmds = [
                'sudo tc qdisc add dev {} root handle 1: htb default 20'.format(iface),

                'sudo tc class add dev {} parent 1: classid 1:1 htb rate {}kbit prio 5'.format(iface, upload_speed),

                # high prio class 1:10
                'sudo tc class add dev {} parent 1:1 classid 1:10 htb rate {}kbit ceil {}kbit prio 1'
                .format(iface, 40 * upload_speed // 100, 95* upload_speed // 100),

                # bulk and default calss 1:20 - gets slightly less traffic and a lower priority
                'sudo tc class add dev {} parent 1:1 classid 1:20 htb rate {}kbit ceil {}kbit prio 2'
                .format(iface, 40 * upload_speed // 100, 95 * upload_speed // 100),

                # traffic we hate
                'sudo tc class add dev {} parent 1:1 classid 1:30 htb rate {}kbit ceil {}kbit prio 3'
                .format(iface, 20 * upload_speed // 100, 90 * upload_speed // 100),

                # all get stochastic fairness
                'sudo tc qdisc add dev {} parent 1:10 handle 10: sfq perturb 10 quantum {}'
                .format(iface, cfg['quantum']),
                'sudo tc qdisc add dev {} parent 1:20 handle 20: sfq perturb 10 quantum {}'
                .format(iface, cfg['quantum']),
                'sudo tc qdisc add dev {} parent 1:30 handle 30: sfq perturb 10 quantum {}'
                .format(iface, cfg['quantum']),

                # TOS min delay (ssh, not scp) in 1:10
                'sudo tc filter add dev {} parent 1: protocol ip prio 10 u32 match ip tos 0x10 0xff flowid 1:10'
                .format(iface),

                # ICMP (ip protocol 1) in the interactive class 1:10 so we can do measurements & impress our friend
                'sudo tc filter add dev {} parent 1: protocol ip prio 11 u32 match ip protocol 1 0xff flowid 1:10'
                .format(iface),

                # prioritize small packets (<64 bytes)
                'sudo tc filter add dev {} parent 1: protocol ip prio 12 u32 match ip protocol 6 0xff match u8'
                ' 0x05 0x0f at 0 match u16 0x0000 0xffc0 at 2 flowid 1:10'.format(iface),

                # non-priority host src
                'sudo tc filter add dev {} parent 1: protocol ip prio 16 u32 match ip src {} flowid 1:30'
                .format(iface, 80),

                # reset is 'non-interactive' i.e. 'bulk' and ends up in 1:20
                'sudo tc filter add dev {} parent 1: protocol ip prio 10 u32 match ip dst 0.0.0.0/0 flowid 1:20'
                .format(iface)
            ]

            rcode, _, _ = util.run_cmd_on_diego_cell(
                app_instance['diego_id'],
                '\n'.join(cmds)
            )
            if rcode:
                logger.error('Failed to limit bandwidth, received error code %d.', rcode)
                self.unmanipulate_network()
                return rcode
        return 0

    def unmanipulate_network(self):
        """
        Undo traffic manipulation changes to the application and its services.
        """
        for app_instance in self.instances:
            cmds = [
                'sudo tc qdisc del dev {} root'.format(app_instance['diego_vi']),
                'sudo tc qdisc del dev {} ingress'.format(app_instance['diego_vi'])
            ]
            util.run_cmd_on_diego_cell(
                app_instance['diego_id'],
                '\n'.join(cmds)
            )

    def kill_monit_process(self, process):
        """
        Kill a monit managed process on all diego cells this application is hosted on. Make sure to bring the process
        back up afterwords!
        :param process: str; Name of the monit job to kill.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        for app_instance in self.instances:
            d_id = app_instance['diego_id']
            rcode, stdout, _ = util.run_cmd_on_diego_cell(
                d_id, 'find /var/vcap/sys/run | grep {} | grep --color=never pid'.format(process)
            )
            pid_files = list(filter(  # filter out garbage ssh lines
                lambda l: ('/var/vcap/sys/run' in l) and ('find /var/vcap/sys/run' not in l),
                stdout.splitlines()
            ))
            if rcode or not pid_files:
                logger.error("Encountered error when discovering monit process.")
                return rcode
            logger.debug("Found pid files %s for %s on %s.", pid_files, process, d_id)

            cmds = ['sudo /var/vcap/bosh/bin/monit unmonitor {}'.format(process)]
            cmds.extend(['sudo kill $(cat {})'.format(pf) for pf in pid_files])
            rcode, _, _ = util.run_cmd_on_diego_cell(d_id, '\n'.join(cmds))
            if rcode:
                logger.error("Encountered error killing monit processes!")
                self.start_monit_process(process)
                return rcode
            return 0

    def start_monit_process(self, process):
        """
        Start a monit process on all diego cells this application is hosted on.
        :param process: str; Name of the monit job to kill.
        """
        for app_instance in self.instances:
            d_id = app_instance['diego_id']
            util.run_cmd_on_diego_cell(d_id, 'sudo /var/vcap/bosh/bin/monit start {}'.format(process))

    def get_services_by_type(self, service_type):
        """
        Get all services of a certain type.
        :param service_type: String; The type of service to filter by.
        :return: List[String]; A list of services of the specified type.
        """
        return [s for s in self.services if s.type == service_type]

    def get_service_by_name(self, service_name):
        """
        Get the service with the specified name. Will return the first one it finds if there is more than one for some
        reason.
        :param service_name: String; The name of the bound service.
        :return: Optional[Service]; The service or None if there was no match.
        """
        for service in self.services:
            if service['name'] == service_name:
                return service

        return None

    @staticmethod
    def _app_port_not_whitelisted(ports):
        cfg = Config()
        return ports[0] not in cfg['host-port-whitelist'] and \
               ports[1] not in cfg['container-port-whitelist']


def find_application_guid(appname):
    """
    Find the GUID of an application using cloud foundry's CLI interface. The GUID acts as a unique identifier for
    the application which we can then use to find what containers are running it.
    :param appname: String; The name of the app to deserialize.
    :return: String; The application GUID.
    """
    assert appname
    cfg = Config()
    cmd = '{} app {} --guid'.format(cfg['cf']['cmd'], appname)
    rcode, stdout, _ = util.run_cmd(cmd)
    guid = stdout.split('\n')[0].rstrip('\r\n')
    if rcode:
        sys.exit("Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(appname))

    logger.debug(guid)
    return guid


def find_application_instances(app_guid):
    """
    Find the containers which host an application by using cfdot.
    :return: Dict[String, DiegoHost]; The diego-cells which host this app and their associated sub-containers.
    """
    cfg = Config()
    cmd = 'cfdot actual-lrp-groups | grep --color=never {}'.format(app_guid)
    rcode, stdout, _ = util.run_cmd_on_diego_cell(cfg['bosh']['cfdot-dc'], cmd)

    if rcode:
        logger.error("Failed retrieving LRP data from %s.", cfg['bosh']['cfdot-dc'])
        return None

    instances = []

    # for each instance, find information about where it is hosted and its connected ports
    for instance in util.extract_json(stdout):
        instance = instance['instance']

        if instance['state'] != 'RUNNING':
            continue

        diego_ip = instance['address']
        cont_ip = instance['instance_address']
        app_ports = set()  # ports the application is listening on within the container

        for ports in instance['ports']:
            diego_port = ports['host_port']  # node port on the diego-cell
            cont_port = ports['container_port']  # port the application is listening on in the container

            if diego_port in cfg['host-port-whitelist']:
                continue
            if cont_port in cfg['container-port-whitelist']:
                continue

            app_ports.add((diego_port, cont_port))
            logger.debug('Found application at %s:%d with container port %d', diego_ip, diego_port, cont_port)

        # Lookup the diego-cell's VM ID in the bosh deployment
        cmd = r"{} -e {} -d {} vms | egrep '\s{}\s' | egrep -o '^diego.cell/[a-z0-9-]*'" \
            .format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_ip.replace('.', r'\.'))
        rcode, stdout, _ = util.run_cmd(cmd)
        if rcode:
            logger.warning("Failed retrieving VM information from BOSH for %s.", diego_ip)
            diego_id = None
        else:
            diego_id = stdout.split('\n')[0].rstrip('\r\n')
            logger.debug("Hosting diego-cell VM: %s.", diego_id)

        # Lookup the virtual network interface
        _, stdout, _ = util.run_cmd_on_diego_cell(diego_id, 'ip a')
        stdout = util.group_lines_by_hanging_indent(stdout)
        index = util.find_string_in_grouping(stdout, cont_ip.replace('.', r'\.'))
        if not index:
            logger.warning("Could not find virtual interface!")
            diego_vi = None
        else:
            diego_vi = stdout[index[0]][0]  # want to get parent of the match
            match = re.match(r'\d+: ([\w-]+)(@[\w-]+)?:', diego_vi)
            assert match  # This should never fail, so the regex must be wrong!
            diego_vi = match[1]
            logger.debug("Hosting diego-cell Virtual Interface: %s", diego_vi)

        # Lookup the Container ID
        cmd = "cat /var/vcap/sys/log/rep/rep.stdout.log | grep {} | tail -n 1".format(cont_ip)
        rcode, stdout, _ = util.run_cmd_on_diego_cell(diego_id, cmd)
        if rcode:
            logger.error("Failed retrieving container GUID from %s.", diego_id)
            cont_id = None
        else:
            cont_id = util.extract_json(stdout)[0]['data']['container-guid']
            logger.debug("Hosting container GUID: %s.", cont_id)

        # Record the app instance information
        app_instance = AppInstance(
            diego_id=diego_id,
            diego_ip=diego_ip,
            cont_id=cont_id,
            cont_ip=cont_ip,
            app_ports=app_ports,
            diego_vi=diego_vi
        )
        instances.append(app_instance)
        logger.info("Found instance: %s", app_instance)
    return instances


def find_application_services(appname):
    """
    Discover all services bound to an application. This will use `cf env` and parse the output for VCAP_SERVICES.
    :param appname: String; The name of the app to deserialize.
    :return: Dict[String, Service]; The list of all services bound to this application.
    """
    cfg = Config()
    rcode, stdout, _ = util.run_cmd('{} env {}'.format(cfg['cf']['cmd'], appname))
    if rcode:
        sys.exit("Failed to query application environment variables.")

    json_objs = util.extract_json(stdout)
    if not json_objs:
        sys.exit("Error reading output from `cf env`")

    for obj in json_objs:
        if 'VCAP_SERVICES' not in obj:
            json_objs.remove(obj)

    if len(json_objs) != 1:
        sys.exit("Could not find VCAP_SERVICES in output.")

    services = []
    vservices = json_objs[0]['VCAP_SERVICES']
    logger.debug(json.dumps(vservices, indent='  '))

    for sname, sconfig in vservices.items():
        for instance_cfg in sconfig:
            service = Service.from_service_info(sname, instance_cfg)
            if service:
                logger.info("Found service: %s", service)
                services.append(service)

    return services
