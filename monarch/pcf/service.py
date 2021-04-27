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

""" A single service which an application is bound to.
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
            syslog_drain_url = credentials.get('syslog_drain_url') or service_config['syslog_drain_url']
            match = re.match(r'syslog://([a-zA-Z0-9_.-]+):(\d+)', syslog_drain_url)
            sip = dnslookup(match[1])
            service['hosts'].add((sip, 'tcp', match[2]))
        elif service['type'] in ['p-mysql', 'p.mysql']:
            service['user'] = credentials['username']
            service['password'] = credentials['password']
            service['hosts'].add((credentials['hostname'], 'tcp', credentials['port']))
        elif service['type'] == 'p-redis':
            service['password'] = credentials['password']
            service['hosts'].add((dnslookup(credentials['host']), 'tcp', credentials['port']))
        elif service['type'] == 'p-rabbitmq':
            service['user'] = credentials['username']
            service['password'] = credentials['password']
            for pconfig in credentials['protocols'].values():
                port = pconfig['port']
                for host in pconfig['hosts']:
                    service['hosts'].add((host, 'tcp', port))
        elif service['type'] == 'p-circuit-breaker-dashboard':
            service['user'] = credentials['amqp']['username']
            service['password'] = credentials['amqp']['password']
            for hostname in credentials['amqp']['protocols']['amqp']['hosts']:
                service['hosts'].add((
                    dnslookup(hostname), 'tcp',
                    credentials['amqp']['protocols']['amqp']['port']))
            for hostname in credentials['amqp']['protocols']['management']['hosts']:
                service['hosts'].add((
                    dnslookup(hostname), 'tcp',
                    credentials['amqp']['protocols']['management']['port']
                ))
        elif re.match("postgresql-\d+-odb", service['type']):
            service['user'] = credentials['username']
            service['password'] = credentials['password']
            service['hosts'].add((credentials['db_host'], 'tcp', credentials['db_port']))
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
