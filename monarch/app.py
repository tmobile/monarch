import sys
import json

from monarch import DEFAULT_ENCODING
from monarch.diegohost import DiegoHost
from monarch.service import Service
from monarch.util import extract_json
from subprocess import Popen, PIPE, DEVNULL
from logzero import logger
from random import shuffle


def discover_app(cfg, org, space, appname):
    """
    Find an application's hosts and services.
    :param cfg: Dict[String, any]; Configuration information about the environment.
    :param org: String; the cloud foundry organization the application is hosted in.
    :param space: String; the cloud foundry organization space the application is hosted in.
    :param appname: String; the name of the application deployment within cloud foundry.
    :return: App; Instance of App which holds all the discovered information.
    """
    app = App(org, space, appname)
    app.find_hosts(cfg)
    app.find_services(cfg)
    return app


class App:
    """
    Information about an application and all of the locations it is hosted.
    """

    def __init__(self, org, space, appname):
        """
        Initialize a new hosted app object.
        :param org: String; the cloud foundry organization the application is hosted in.
        :param space: String; the cloud foundry organization space the application is hosted in.
        :param appname: String; the name of the application deployment within cloud foundry.
        """

        self.org = org
        self.space = space
        self.appname = appname
        self.guid = None
        self.diego_hosts = {}
        self.services = {}

    def __iter__(self):
        """
        Iterate over each of the diego-cells the application is hosted on.
        :return: Iter; An iterator over the diego-cells the application is hosted on.
        """
        return self.diego_hosts.__iter__()

    def __contains__(self, item):
        """
        Check if a given diego-cell is listed as a host of this application.
        :param item: String; The IP of the diego-cell.
        :return: bool; Whether the diego-cell is a known of this application.
        """
        return self.diego_hosts.__contains__(item)

    def __len__(self):
        """
        Find how many diego-cells host this application.
        :return: int; The number of diego-cells which host this application.
        """
        return len(self.diego_hosts)

    def __hash__(self):
        """
        Calculate a unique identifier for this application based on its organization, space, and application name.
        :return: A unique identifier for this application.
        """
        return hash(self.id())

    def __getitem__(self, item):
        """
        Retrieve information about a diego-cell which hosts this application.
        :param item: String; The IP address of the diego-cell in question.
        :return: DiegoHost; The diego-cell with the given IP address.
        """
        return self.diego_hosts[item]

    def __setitem__(self, key, value):
        """
        Specify a diego-cell host of this application.
        :param key: String; The IP address of the diego-cell.
        :param value: DiegoHost; Thew diego-cell information.
        """
        self.diego_hosts[key] = value

    def __delitem__(self, key):
        """
        Remove a diego-cell as a known host of this application.
        :param key: String; The IP address of the diego-cell.
        """
        return self.diego_hosts.__delitem__(key)

    def __repr__(self):
        return 'App({}:{}:{})'.format(self.org, self.space, self.appname)

    def id(self):
        """
        Create a unique descriptor for this application. It will take the form 'org_space_appname'.
        :return: String; A unique descriptor for this application.
        """
        return '{}_{}_{}'.format(self.org, self.space, self.appname)

    def add_diego_cell(self, dc):
        """
        Adds a diego cell as a host of this app. It will merge any of the internal container information if the new
        diego-cell is already present.
        :param dc: DiegoHost; The new Diego-cell to add/merge
        """
        if dc.ip in self.diego_hosts:
            d_host = self.diego_hosts[dc.ip]
            for cont_ip, cont_ports in dc.containers.items():
                d_host.add_instance(cont_ip, cont_ports)
        else:
            self.diego_hosts[dc.ip] = dc

    def add_service(self, service):
        """
        Adds a service as a dependency of this app. It will merge any of the service information if the new service
        has the same type and name as one which is already present.
        :param service: Service; The new Service to add/merge.
        """
        sid = service.id()
        if sid in self.services:
            e_service = self.services[sid]
            assert e_service.user == service.user and e_service.pswd == service.pswd
            e_service.hosts |= service.hosts  # union the hosts
        else:
            self.services[service.id()] = service

    def instances(self):
        """
        Get a list of all application instances.
        :return: List[(str, str)]; List of all application instances diego-cell and container ips.
        """
        instances = []
        for dc in self.diego_hosts.values():
            for container_ip in dc.containers.keys():
                instances.append((dc.vm, container_ip))
        return instances

    def find_hosts(self, cfg):
        """
        Find all diego-cells and respective containers which host this application. This will first find the GUID of the
        CF application and then find what diego-cells and containers are running the application. It will update the
        internal hosts lists as well as return the information.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: Dict[String, DiegoHost]; The list of diego-cells which host this application.
        """
        self._find_guid(cfg)
        self._find_container_hosts(cfg)

        for dc in self.diego_hosts.values():
            dc.find_diego_vm_name(cfg)

        return self.diego_hosts

    def find_services(self, cfg):
        """
        Discover all services bound to this application. This will use `cf env` and parse the output for VCAP_SERVICES.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: Dict[String, Service]; The list of all services bound to this application.
        """
        cmd = '{} env {}'.format(cfg['cf']['cmd'], self.appname)
        logger.debug('> ' + cmd)
        with Popen(cmd.split(' '), stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            if proc.returncode:
                sys.exit("Failed to query application environment variables.")

            lines = proc.stdout.readlines()

        json_objs = extract_json(''.join(lines))
        if not json_objs:
            sys.exit("Error reading output from `cf env`")

        for obj in json_objs:
            if 'VCAP_SERVICES' not in obj:
                json_objs.remove(obj)

        if len(json_objs) != 1:
            sys.exit("Could not find VCAP_SERVICES in output.")

        services = json_objs[0]['VCAP_SERVICES']
        logger.debug(json.dumps(services, indent='  '))

        for service, sconfig in services.items():
            if service in cfg['service-whitelist']:
                continue

            for instance_cfg in sconfig:
                s = Service.from_service_info(service, instance_cfg)
                if s:
                    logger.info("Found service: {}".format(s))
                    self.add_service(s)

        return self.services

    def crash_random_instance(self, cfg, count=1):
        """
        Crash one or more random application instances.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :param count: int; Number of instances to crash.
        """
        instances = self.instances()
        count = min(count, len(instances))
        shuffle(instances)
        instances = instances[:count]

        for (diego_cell, container_ip) in instances:
            logger.debug('Blocking container at {}.'.format(container_ip))
            cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'],
                                                 diego_cell)
            logger.debug('$ ' + cmd)
            with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
                cmd = "cat /var/vcap/sys/log/rep/rep.stdout.log | grep {} | tail -n 1 && exit".format(container_ip)
                logger.debug('$> ' + cmd)
                stdout, _ = proc.communicate(input=cmd + '\n', timeout=30)
                if proc.returncode:
                    logger.error("Failed retrieving container GUID from {}".format(diego_cell))
                    continue

            container_guid = extract_json(stdout)[0]['data']['container-guid']
            logger.info('Crashing app instance at {} with container {}:{}.'.format(diego_cell, container_ip,
                                                                                   container_guid))
            cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'],
                                                 diego_cell)
            logger.debug('$ ' + cmd)
            with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
                cmd = "sudo /var/vcap/packages/runc/bin/runc exec {} /usr/bin/pkill -SIGSEGV java && exit"\
                    .format(container_guid)
                logger.debug('$> ' + cmd)
                proc.communicate(input=cmd + '\n', timeout=30)
                if proc.returncode:
                    logger.error("Failed to crash application container {}:{}.".format(container_guid, container_ip))

    def block(self, cfg):
        """
        Block access to this application on all its known hosts.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.block(cfg)

            if ret:
                logger.warn("Could not block host {}.".format(dc.vm))
                return ret

        return 0

    def unblock(self, cfg):
        """
        Unblock access to this application on all its known hosts. This will actually run the unblock commands multiple
        times, as defined by `TIMES_TO_REMOVE` to prevent issues if an application was blocked multiple times.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.unblock(cfg)

            if ret:
                logger.warn("Could not unblock host {}.".format(dc.vm))
                return ret

        return 0

    def block_services(self, cfg, services=None):
        """
        Block this application from accessing its services on all its known hosts.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :param services: List[String]; List of service names to block, will target all if unset.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """

        for dc in self.diego_hosts.values():
            fserv = self.services.values()
            if services is not None:
                # an empty list is not equivalent to None
                fserv = filter(lambda s: s.name in services, fserv)

            ret = dc.block_services(cfg, fserv)

            if ret:
                if services is not None:
                    logger.warn("Could not block {} on host {}".format(services, dc.vm))
                else:
                    logger.warn("Could not block all services on host {}".format(dc.vm))
                return ret

        return 0

    def unblock_services(self, cfg, services=None):
        """
        Unblock this application from accessing its services on all its known hosts.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :param services: List[String]; List of service names to unblock, will target all if unset.
        :return: int; A returncode if any of the bosh ssh instances do not return 0.
        """
        for dc in self.diego_hosts.values():
            fserv = self.services.values()
            if services is not None:
                # an empty list is not equivalent to None
                fserv = filter(lambda s: s.name in services, fserv)

            ret = dc.unblock_services(cfg, fserv)

            if ret:
                if services is not None:
                    logger.warn("Could not unblock {} on host {}".format(services, dc.vm))
                else:
                    logger.warn("Could not unblock all services on host {}.".format(dc.vm))
                return ret

        return 0

    def get_services_by_type(self, service_type):
        """
        Get all services of a certain type.
        :param service_type: String; The type of service to filter by.
        :return: List[String]; A list of services of the specified type.
        """
        matching = []
        for service in self.services.values():
            if service_type == service.type:
                matching.append(service)
        return matching

    def get_service_by_name(self, service_name):
        """
        Get the service with the specified name. Will return the first one it finds if there is more than one for some
        reason.
        :param service_name: String; The name of the bound service.
        :return: Optional[Service]; The service or None if there was no match.
        """
        for service in self.services.values():
            if service_name == service.name:
                return service

        return None

    def serialize(self, obj=None, wrap=True):
        """
        Convert this class into a dictionary representation of itself.
        :param obj: Dict[String, any]; A dictionary to serialize into and merge information with. The keys should be in the form `org_space_appname`.
        :param wrap: bool; Whether we should wrap the result in it's ID. Only alters what we return; still assumes obj is wrappped.
        :return: Dict[String, any]; A dictionary representation of this object.
        """
        if obj is None:
            obj = {}

        if self.id() in obj:
            app = obj[self.id()]
            assert self._validate_japp(app)
        else:
            app = {
                'appname': self.appname,
                'org': self.org,
                'space': self.space,
                'diego_hosts': {},
                'services': {}
            }

        for dc in self.diego_hosts.values():
            dc.serialize(obj=app['diego_hosts'])

        for service in self.services.values():
            service.serialize(obj=app['services'])

        obj[self.id()] = app
        return obj if wrap else app

    @staticmethod
    def deserialize(obj, org, space, appname, readonly=False, wrapped=True):
        """
        Convert a dictionary representation of this class into an instance of this class.
        :param obj: Dict[String, any]; Dictionary to deserialize from in the form {"org_space_app": {App}, ...}.
        :param org: String; The organization of the app to deserialize.
        :param space: String; The space of the app to deserialize.
        :param appname: String; The name of the app to deserialize.
        :param readonly: bool; Whether we should modify the object by removing the specified app.
        :param wrapped: bool; Whether we should assume the obj we receive is wrapped with the obj id.
        :return: Option[App]; An instance of this class or None if it is not in the dictionary.
        """
        self = App(org, space, appname)
        if wrapped:
            app = obj.get(self.id(), None) if readonly else obj.pop(self.id(), None)
        else:
            app = obj

        if app is None:
            return None

        assert self._validate_japp(app)

        for ip in app['diego_hosts']:
            dc = DiegoHost.deserialize(app['diego_hosts'], ip)
            self.add_diego_cell(dc)

        for sid in app['services']:
            service = Service.deserialize(app['services'], sid)
            self.add_service(service)

        return self

    def _validate_japp(self, japp):
        """
        Quick way to verify a dictionary representation of an app is valid. This is used to validate json information.
        :param japp: Dict[String, any]; Dictionary object to validate.
        :return: Whether it is a valid application representation.
        """
        return \
            japp['appname'] == self.appname and \
            japp['org'] == self.org and \
            japp['space'] == self.space

    def _find_guid(self, cfg):
        """
        Find the GUID of an application using cloud foundry's CLI interface. The GUID acts as a unique identifier for
        the application which we can then use to find what containers are running it.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: String; The application GUID.
        """
        cmd = '{} app {} --guid'.format(cfg['cf']['cmd'], self.appname)
        logger.debug('$ ' + cmd)
        with Popen(cmd.split(' '), stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            guid = proc.stdout.readline().rstrip('\r\n')
            if proc.returncode:
                sys.exit(
                    "Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(
                        self.appname))

        self.guid = guid
        logger.debug(guid)
        return guid

    def _find_container_hosts(self, cfg):
        """
        Find the containers which host this application by using cfdot.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: Dict[String, DiegoHost]; The diego-cells which host this app and their associated sub-containers.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'],
                                             cfg['bosh']['cfdot-dc'])
        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            cmd = 'cfdot actual-lrp-groups | grep --color=never {} && exit'.format(self.guid)
            logger.debug('$> ' + cmd)
            stdout, _ = proc.communicate(input=cmd + '\n', timeout=30)
            if proc.returncode:
                sys.exit("Failed retrieving LRP data from {}".format(cfg['bosh']['cfdot-dc']))

            json_objs = extract_json(stdout)
            for obj in json_objs:
                instance = obj['instance']

                if instance['state'] != 'RUNNING':
                    continue

                host_ip = instance['address']
                cont_ip = instance['instance_address']
                cont_ports = set()

                for p in instance['ports']:
                    host_port = p['host_port']
                    cont_port = p['container_port']

                    if host_port in cfg['host-port-whitelist']:
                        continue
                    if cont_port in cfg['container-port-whitelist']:
                        continue

                    cont_ports.add(cont_port)
                    logger.info(
                        'Found application at {}:{} with container port {}'.format(host_ip, host_port, cont_port))

                host = DiegoHost(host_ip)
                host.add_instance(cont_ip, cont_ports)
                self.add_diego_cell(host)

        return self.diego_hosts
