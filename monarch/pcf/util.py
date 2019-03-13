""" PCF util functions.

    Copyright 2019 T-Mobile US, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

from monarch.pcf.config import Config
from monarch.util import run_cmd


def cf_target(org, space):
    """
    Target a specific organization and space using the cloud foundry CLI. This should be run before anything which calls
    out to cloud foundry. This will fail if cloud foundry is not logged in.
    :param org: The organization to target.
    :param space: The space within the organization to target.
    :return: The returncode of the cloud foundry CLI.
    """
    cfg = Config()
    rcode, _, _ = run_cmd([cfg['cf']['cmd'], 'target', '-o', org, '-s', space])
    return rcode


def bosh_cli(args, stdin=None, env=None, dep=None):
    """
    Call the bosh CLI.
    :param args: Union[List[str], str]; Arguments for the bosh CLI. This will allow chaining additional commands
    with '&&', '|', etc.
    :param env: str; The bosh environment to use. Defaults to config value.
    :param dep: str; The bosh deployment to use. Defaults to configured cf deployment value.
    :param stdin: Optional[Union[str, List[Union[str, List[str]]]]]; Input to pipe to the program.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    boshcfg = Config()['bosh']
    cmd = [boshcfg['cmd'], '-e', env or boshcfg['env'], '-d', dep or boshcfg['cf-dep']]
    if isinstance(args, list):
        cmd.extend(args)
    else:
        cmd.append(args)
    return run_cmd(cmd, stdin=stdin)


def run_cmd_on_diego_cell(dcid, cmd):
    """
    Run one or more commands in the shell on a diego cell.
    :param dcid: str; Diego-cell ID of the Diego Cell which is to be connected to.
    :param cmd: Union[str, List[str]]; Command(s) to run on the Diego Cell.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    if isinstance(cmd, list):
        cmd.append('exit')
    else:
        cmd = [cmd, 'exit']
    return bosh_cli(['ssh', dcid], cmd)


def run_cmd_on_container(dcid, contid, cmd):
    """
    Run one or more commands in the shell on a container on a diego cell.
    :param dcid: str; Diego-cell ID of the Diego Cell running the container.
    :param contid: str; Container ID of the container which is to be connected to.
    :param cmd: Union[str, List[str]]; Command(s) to run on the container.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    shell_cmd = 'exec sudo /var/vcap/packages/runc/bin/runc exec -t {} /bin/bash'.format(contid)
    if isinstance(cmd, list):
        cmd.insert(0, shell_cmd)
    else:
        cmd = [shell_cmd, cmd]
    return run_cmd_on_diego_cell(dcid, cmd)
