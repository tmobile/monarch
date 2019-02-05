from subprocess import Popen, DEVNULL, PIPE
from monarch import DEFAULT_ENCODING, TIMES_TO_REMOVE
from logzero import logger


class DiegoHost:
    """
    This represents a Diego-cell running in a BOSH environment. It contains the ip and name of the Diego-cell, and it
    stores all the containers hosting the app that are within thee specific Diego-cell. The container hosts are listed
    as a mapping from the container IP to the application ports, e.g. {"10.5.34.2": set([80, 8080]), ...}
    """

    def __init__(self, ip):
        """
        Initialize a new Diego-cell representation.
        :param ip: String; IP of this diego-cell.
        """
        self.ip = ip
        self.vm = None
        self.containers = {}

    def __iter__(self):
        """
        Iterate over the containers in this Diego-cell.
        :return: Iter; An iterator over the containers in this Diego-cell.
        """
        return self.containers.__iter__()

    def __contains__(self, item):
        """
        Check if this Diego-cell contains a given container.
        :param item: String; The container IP.
        :return: bool; Whether the container is in this Diego-cell.
        """
        return self.containers.__contains__(item)

    def __len__(self):
        """
        Find how many containers are within this Diego-cell.
        :return: int; The number of containers within this Diego-cell.
        """
        return len(self.containers)

    def __hash__(self):
        """
        A unique identifier for this Diego-cell based on its IP.
        :return: A hash of this Diego-cell's IP.
        """
        return hash(self.ip)

    def __getitem__(self, cont_ip):
        """
        Get a container within this Diego-cell by its IP.
        :param cont_ip: String; IP of the container in question.
        :return: Set[int]; The set of ports on that container the application is attached to.
        """
        return self.containers[cont_ip]

    def __setitem__(self, key, value):
        """
        Set the ports the application is attached to for the given container.
        :param key: String; The container IP for which the ports are relevant.
        :param value: Set[int]; Set of ports the application is bound to.
        """
        self.containers[key] = value

    def __delitem__(self, key):
        """
        Remove a container and its set of ports.
        :param key: String; The container IP.
        """
        return self.containers.__delitem__(key)

    def __repr__(self):
        return 'DiegoHost({}:{})'.format(self.ip, self.vm)

    def add_instance(self, cont_ip, cont_ports):
        """
        Add a new container or new container ports. It will automatically merge ports instead of replacing the existing
        entry if there is already information for the specified container.
        :param cont_ip: String; IP Address of the container hosted on this diego-cell.
        :param cont_ports: Set[int]; The set of ports which the application is bound to on the container.
        """
        ports = self.containers.get(cont_ip, set())
        ports |= cont_ports
        self[cont_ip] = ports

    def find_diego_vm_name(self, cfg):
        """
        Query bosh for the VM name of this diego cell given its IP address. This will simply return the current VM name
        if it has already been found.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: Optional[String]; The VM name.
        """
        if self.vm:
            return self.vm

        cmd = "{} -e {} -d {} vms | grep -P '\s{}\s' | grep -Po '^diego.cell/[a-z0-9-]*'" \
            .format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.ip.replace('.', '\.'))

        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            if proc.returncode:
                logger.warn("Failed retrieving VM information from BOSH for {}.".format(self.ip))
                return None
            self.vm = proc.stdout.readline().rstrip('\r\n')
            logger.debug(self.vm)

        return self.vm

    def block(self, cfg):
        """
        Block the application on this diego-cell. It will create new iptables rules on the diego-cell to block all
        traffic forwarded to the application.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: int; The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    logger.info("Targeting {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    cmd = 'sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP'.format(cont_ip, cont_port)
                    logger.debug('$> ' + cmd)
                    proc.stdin.write(cmd + '\n')

            logger.debug('$> exit')
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def unblock(self, cfg):
        """
        Unblock the application on this diego-cell. It will delete the iptables rule on this diego-cell based on its
        description. (i.e. it does not blindly delete the first item which allows multiple different apps to be blocked
        on the same diego-cell.)
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :return: int; The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    logger.info("Unblocking {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    cmd = 'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP'.format(cont_ip, cont_port)
                    logger.debug('$> ' + cmd)
                    for _ in range(TIMES_TO_REMOVE):
                        proc.stdin.write(cmd + '\n')
            logger.debug("$> exit")
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def block_services(self, cfg, services):
        """
        Block instances of the application hosted on this DiegoCell from being able to reach and of the specified
        services.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :param services: Iterable[Service]; List of services to be blocked.
        :return: The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, _ in self.containers.items():
                for service in services:
                    logger.info("Targeting {} on {}".format(service.name, self.vm))
                    service.block(proc.stdin, cont_ip)

            logger.debug('$> exit')
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def unblock_services(self, cfg, services):
        """
        Unblock instances of the application hosted on this DiegoCell from being able to reach and of the specified
        services.
        :param cfg: Dict[String, any]; Configuration information about the environment.
        :param services: Iterable[Service]; List of services to be blocked.
        :return: int; The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        logger.debug('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, _ in self.containers.items():
                for service in services:
                    logger.info("Unblocking {} on {}".format(service.name, self.vm))
                    service.unblock(proc.stdin, cont_ip)

            logger.debug('$> exit')
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def serialize(self, obj=None):
        """
        Convert this class into a dictionary representation of itself.
        :param obj: Dict[String, any]; A dictionary to serialize into and merge information with. The keys should be the IPs of DiegoHosts.
        :return: Dict[String, any]; A dictionary representation of this object.
        """
        if obj is None:
            obj = {}

        if self.ip in obj:
            jdc = obj[self.ip]
            assert jdc['vm'] == self.vm
            assert jdc['ip'] == self.ip
        else:
            jdc = {
                'ip': self.ip,
                'vm': self.vm,
                'containers': {}
            }

        for cont_ip, cont_ports in self.containers.items():
            jports = set(jdc.get(cont_ip, []))
            jdc['containers'][cont_ip] = list(jports | cont_ports)

            obj[self.ip] = jdc

        return obj

    @staticmethod
    def deserialize(obj, ip):
        """
        Convert a dictionary representation of this class into an instance of this class.
        :param obj: Dict[String, any]; Dictionary to deserialize from in the form {"IP": {DiegoHost}, ...}.
        :param ip: String; The IP of the DiegoHost to deserialize.
        :return: DiegoHost; An instance of this class.
        """
        self = DiegoHost(ip)
        jdc = obj[ip]
        assert jdc['ip'] == ip
        self.vm = jdc['vm']

        for cont_ip, cont_ports in jdc['containers'].items():
            self.add_instance(cont_ip, set(cont_ports))

        return self
