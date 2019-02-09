"""
A single service which an application is bound to.
"""

import re
from socket import gethostbyname as dnslookup
from logzero import logger


class Service(dict):
    """
    This represents a service which is bound to the application through cloud foundry. It contains information about the
    service such as where it is hosted and what ports it is accessed through as well as general service information like
    the username and password, service name, and service type.

    type: String; type of service; e.g. 'p-mysql'.
    name: String; name of this service instance (this is the name given when creating the service).
    user: String; username credential for this service.
    password: String; password credential for this service.
    hosts: Set[(String, String, String)]; Set of (IP, Protocol, Port) tuples for where this service is hosted.
    """

    @staticmethod
    def from_service_info(service_type, service_config):
        """
        Given a service configuration object and the name of the service, extract the hosts and username/password
        (if relevant).
        :param service_type: String; Name of the service the configuration is for, e.g. are 'p-mysql' or
        'p-config-server'.
        :param service_config: Optional[Dict[String, any]]; Configuration object from VCAP_SERVICES for the provided
        service. Note, it is for one instance.
        :return: Service
        """
        service = Service()
        service['type'] = service_type
        service['name'] = service_config['name']
        service['user'] = None
        service['password'] = None
        service['hosts'] = set()

        credentials = service_config.get('credentials', None)

        if service['type'] == 'p-config-server':
            service['user'] = credentials['client_id']
            service['password'] = credentials['client_secret']
            match = re.match(r'https://([a-zA-Z0-9_.-]+):?(\d+)?', credentials['uri'])
            sip = dnslookup(match[1])  # from my testing, the diego-cells *should* find the same values
            port = match[2] or '443'
            service['hosts'].add((sip, 'tcp', port))
        elif service['type'] == 'p-service-registry':
            service['user'] = credentials['client_id']
            service['password'] = credentials['client_secret']
            match = re.match(r'https://([a-zA-Z0-9_.-]+):?(\d+)?', credentials['uri'])
            sip = dnslookup(match[1])
            port = match[2] or 'all'
            service['hosts'].add((sip, 'tcp', port))
        elif service['type'] == 'T-Logger':
            match = re.match(r'syslog://([a-zA-Z0-9_.-]+):(\d+)', credentials['syslog_drain_url'])
            sip = dnslookup(match[1])
            service['hosts'].add((sip, 'tcp', match[2]))
        elif service['type'] == 'p-mysql':
            service['user'] = credentials['username']
            service['password'] = credentials['password']
            service['hosts'].add((credentials['hostname'], 'tcp', credentials['port']))
        elif service['type'] == 'p-rabbitmq':
            service['user'] = credentials['username']
            service['password'] = credentials['password']
            for pconfig in credentials['protocols'].values():
                port = pconfig['port']
                for host in pconfig['hosts']:
                    service['hosts'].add((host, 'tcp', port))
        else:
            logger.warning("Unrecognized service '%s'", service['type'])

        return service

    def serialize(self):
        """
        Convert this application instance into a serializable dictionary.
        :return: Serializable dictionary representation of the app instance.
        """
        obj = self.copy()
        obj['hosts'] = [h for h in self['hosts']]
        return obj
