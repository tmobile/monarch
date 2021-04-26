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

""" PCF util functions.
"""
from tempfile import NamedTemporaryFile

from monarch.pcf.config import Config
from monarch.util import run_cmd


def bosh_cli(args, stdin=None, env=None, dep=None, suppress_output=False):
    """
    Call the bosh CLI.
    :param args: Union[List[str], str]; Arguments for the bosh CLI. This will allow chaining additional commands
    with '&&', '|', etc.
    :param env: str; The bosh environment to use. Defaults to config value.
    :param dep: str; The bosh deployment to use. Defaults to configured cf deployment value.
    :param stdin: Optional[Union[str, List[Union[str, List[str]]]]]; Input to pipe to the program.
    :param suppress_output: bool; If true, no extra debug output will be printed when an error occurs.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    boshcfg = Config()['bosh']
    certfile = Certfile()
    cmd = [boshcfg['cmd'], '-e', env or boshcfg['env'], '-d', dep or boshcfg['cf-dep']]
    if certfile:
        cmd.extend(['--ca-cert=' + certfile.name])
    if isinstance(args, list):
        cmd.extend(args)
    else:
        cmd.append(args)
    res = run_cmd(cmd, stdin=stdin, suppress_output=suppress_output)
    return res


def run_cmd_on_diego_cell(dcid, cmd, suppress_output=False):
    """
    Run one or more commands in the shell on a diego cell.
    :param dcid: str; Diego-cell ID of the Diego Cell which is to be connected to.
    :param cmd: Union[str, List[str]]; Command(s) to run on the Diego Cell.
    :param suppress_output: bool; If true, no extra debug output will be printed when an error occurs.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    if isinstance(cmd, list):
        cmd.append('exit')
    else:
        cmd = [cmd, 'exit']
    return bosh_cli(['ssh', dcid], cmd, suppress_output=suppress_output)


def run_cmd_on_container(dcid, contid, cmd, suppress_output=False):
    """
    Run one or more commands in the shell on a container on a diego cell.
    :param dcid: str; Diego-cell ID of the Diego Cell running the container.
    :param contid: str; Container ID of the container which is to be connected to.
    :param cmd: Union[str, List[str]]; Command(s) to run on the container.
    :param suppress_output: bool; If true, no extra debug output will be printed when an error occurs.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    cfg = Config()
    use_containerd = cfg.get("use-containerd") is not None
    if use_containerd:
        # Refer to: https://devops.stackexchange.com/a/13781/27344
        shell_cmd = f'exec sudo /var/vcap/packages/containerd/bin/ctr -a /var/vcap/sys/run/containerd/containerd.sock -n garden tasks exec --exec-id my-shell --tty {contid} /bin/bash'
    else:
        shell_cmd = f'exec sudo /var/vcap/packages/runc/bin/runc exec -t {contid} /bin/bash'
    if isinstance(cmd, list):
        cmd.insert(0, shell_cmd)
    else:
        cmd = [shell_cmd, cmd]
    return run_cmd_on_diego_cell(dcid, cmd, suppress_output=suppress_output)


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


def bosh_login(*, user=None, pswd=None, cacert=None, env=None):
    """
    Login to the bosh CLI. All parameters default to config values if not specified.
    :param user: Bosh username.
    :param pswd: Bosh password.
    :param cacert: Bosh client cert.
    :param env: Bosh environment to login to.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    cfg = Config()['bosh']
    certfile = Certfile(cacert=cacert)

    creds = cfg.get('credentials')
    if not creds:
        assert user and pswd, "Must specify username and password!"
    else:
        user = user or creds['user']
        pswd = pswd or creds['pswd']

    cmd = [cfg['cmd'], '-e', env or cfg['env']]
    stdin = [user, pswd]
    if certfile:
        cmd.extend(['--ca-cert=' + certfile.name])
    cmd.append('login')
    return run_cmd(cmd, stdin)


def cf_login(*, user=None, pswd=None, api=None, skip_ssl_validation=None):
    """
    Login to the CF CLI. All parameters default to config values if not specified.
    :param user: str; Cf username.
    :param pswd: str; Cf password.
    :param api: str; Cf api url.
    :param skip_ssl_validation: bool; Whether cf ssl validation should be skipped, useful if certs are not installed.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    cfg = Config()['cf']
    creds = cfg.get('credentials')
    if not creds:
        assert user and pswd and api, "Must specify username, password, and API address!"
    else:
        user = user or creds['user']
        pswd = pswd or creds['pswd']
        if skip_ssl_validation is None:
            skip_ssl_validation = creds.get('skip-ssl-validation') or False
    pswd = '"{}"'.format(pswd.replace('"', r'\"'))
    api = api or creds['api']
    cmd = [cfg['cmd'], 'login']
    if skip_ssl_validation:
        cmd.append('--skip-ssl-validation')
    cmd.extend(['-a', api, '-u', user, '-p', pswd])
    return run_cmd(cmd, stdin='\n')


class Certfile():
    """Internal-use RAII wrapper for certfiles used by bosh command line."""

    def __init__(self, cacert=None):
        """
        Get the certfile from the config if it exists, otherwise just init to None.
        :param cacert: str; Cert override (instead of reading config).
        """
        self._crtfile = None
        self.name = None

        if not cacert:
            creds = Config()['bosh'].get('credentials')
            if creds:
                cacert = creds.get('cacert')
        if cacert:
            self._crtfile = NamedTemporaryFile(mode='w')
            self._crtfile.write(cacert)
            self._crtfile.flush()
            self.name = self._crtfile.name

    def __del__(self):
        """Close out the temporary file."""
        if self._crtfile:
            self._crtfile.close()

    def __bool__(self):
        """Check if this exists."""
        return self._crtfile is not None
