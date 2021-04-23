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

""" High-level bosh logic and commands.
"""

import json

from logzero import logger

import monarch.pcf.util
from monarch import util
from monarch.pcf.config import Config
from monarch.util import filter_map


def get_vms(env=None, dep=None):
    """
    Get a list of the bosh vms for a deployment.

    :param env: str; The bosh environment to use. Defaults to config value.
    :param dep: str; The bosh deployment to use. Defaults to configured cf deployment value.
    :return: List[VM]; Example VM object:
    ```
    {
        'active': True,
        'az': 'TT-STG02-AZ3',
        'instance': {
            'type': 'syslog_adapter',
            'id': '8823e356-9b79-434b-8e03-d3c60986bb86'
        }
        'ips': '10.94.173.19',
        'process_state': 'running',
        'vm_cid': 'vm-37039d4a-2fba-420f-8508-6f790a878e0c',
        'vm_type': 'medium.disk'
    }
    ```
    """
    rcode, stdout, _ = monarch.pcf.util.bosh_cli('vms --json', env=env, dep=dep)
    if rcode:
        logger.error("Failed retrieving VM information from BOSH.")
        return None
    vms = json.loads(stdout)['Tables'][0]['Rows']
    for vmi in vms:
        vmi['active'] = vmi['active'] == 'true'
        instance = vmi['instance'].split('/')
        vmi['instance'] = {'type': instance[0], 'id': instance[1]}
    return vms


def get_apps():
    """
    Get the apps deployed in the cloud foundry cluster.
    :return: Example app object:
    ```
    {
        'app_guid': '57c6b9cc-7e48-4178-a8fc-a312afcdb42a'
        'process_guid': '57c6b9cc-7e48-4178-a8fc-a312afcdb42a-3d4c0341-31f1-49b3-8a49-41e100122fd6',
        'index': 0,
        'domain': 'cf-apps',
        'instance_guid': 'b39b4d2a-f36d-4aaf-42a9-0d1f',
        'cell_id': '373e05d9-270f-4358-935e-7af712078c4a',
        'address': '10.94.173.17',
        'ports': [
            {
                'container_port': 8080,
                'host_port': 61028,
                'container_tls_proxy_port': 61001,
                'host_tls_proxy_port': 61094
            },
            {
                'container_port': 2222,
                'host_port': 61029,
                'container_tls_proxy_port': 61002,
                'host_tls_proxy_port': 61095
            }
        ],
        'instance_address': '198.19.84.194',
        'crash_count': 0,
        'state': 'RUNNING',
        'since': 1551811902829311393,
        'modification_tag': {
            'epoch': '522dc0a9-88f9-4314-7ceb-5ee8a6402f85',
            'index': 2
        }
    }
    ```
    """
    cfg = Config()
    rcode, stdout, _ = monarch.pcf.util.run_cmd_on_diego_cell(
        cfg['bosh']['cfdot-dc'],
        ['source /etc/profile.d/cfdot.sh', 'cfdot actual-lrp-groups']
    )
    if rcode:
        logger.error("Failed retrieving actual LRP grups from %s", cfg['bosh']['cfdot-dc'])
        return None
    apps = []
    for app in util.extract_json(stdout):
        app = app['instance']
        app['app_guid'] = app['process_guid'][:36]
        apps.append(app)
    return apps


def get_apps_in_diego_cell(diego_cell):
    """
    Get a list of all applications hosted on a specific diego-cell.
    :param diego_cell: str; Diego-cell ID.
    :return: List[str]; GUIDs of the apps running on the diego cell.
    """
    return list(filter_map(
        lambda ai: ai['app_guid'] if ai['cell_id'] == diego_cell else None,
        get_apps()
    ))
