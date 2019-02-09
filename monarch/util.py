"""
Utilities to help reduce code duplication.
"""

import json
from subprocess import Popen, PIPE
from logzero import logger

from monarch.config import Config


def run_cmd(cmd, stdin=None):
    """
    Run a command in the shell.
    :param cmd: str; Command to run.
    :param stdin: Optional[str]; Input to pipe to the program.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    logger.debug('$ %s', cmd)
    try:
        with Popen(cmd, shell=True, stdin=(PIPE if stdin else None), stdout=PIPE, stderr=PIPE, encoding='utf8') as proc:
            if stdin:
                logger.debug('$> %s', stdin)
                stdout, stderr = proc.communicate(input=stdin + '\n', timeout=30)
            else:
                proc.wait(timeout=30)
                stdout = proc.stdout.read()
                stderr = proc.stderr.read()
            rcode = proc.returncode
    except Exception as err:
        logger.warning(err)
        return 1, '', ''
    # logger.debug("STDOUT:\n" + stdout)
    # logger.debug("STDERR:\n" + stderr)
    return rcode, stdout, stderr


def run_cmd_on_diego_cell(dcid, cmd):
    """
    Run a command in the shell.
    :param dcid: str; Diego-cell ID of the Diego Cell which is to be connected to.
    :param cmd: str; Command to run on the Diego Cell.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    cfg = Config()
    return run_cmd(
        ' '.join([cfg['bosh']['cmd'], '-e', cfg['bosh']['env'], '-d', cfg['bosh']['cf-dep'], 'ssh', dcid]),
        cmd
    )


def cf_target(org, space):
    """
    Target a specific organization and space using the cloud foundry CLI. This should be run before anything which calls
    out to cloud foundry. This will fail if cloud foundry is not logged in.
    :param org: The organization to target.
    :param space: The space within the organization to target.
    :return: The returncode of the cloud foundry CLI.
    """
    cfg = Config()
    rcode, _, _ = run_cmd('{} target -o {} -s {}'.format(cfg['cf']['cmd'], org, space))
    return rcode


def extract_json(string):
    """
    Extract JSON from a string by scanning for the start `{` and end `}`. It will extract this from a string and then
    load it as a JSON object. If multiple json objects are detected, it will create a list of them. If no JSON is found,
    then None will be returned.
    :param string: String; String possibly containing one or more JSON objects.
    :return: Optional[list[dict[String, any]]]; A list of JSON objects or None.
    """
    depth = 0
    obj_strs = []
    for index, char in enumerate(string):
        if char == '{':
            depth += 1

            if depth == 1:
                start = index
        elif char == '}' and depth > 0:
            depth -= 1

            if depth == 0:
                obj_strs.append(string[start:index+1])

    if not obj_strs:
        return None

    objs = []
    for string in obj_strs:
        try:
            objs.append(json.loads(string))
        except json.JSONDecodeError:
            # ignore it and move on
            pass
    return objs
