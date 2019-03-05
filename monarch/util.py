"""
Utilities to help reduce code duplication.
"""

import json
import re
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
    # logger.debug("STDOUT:\n%s", stdout)
    # logger.debug("STDERR:\n%s", stderr)
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
        cmd + '\nexit'
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
                obj_strs.append(string[start:index + 1])

    if not obj_strs:
        return None

    objs = []
    for obj_str in obj_strs:
        try:
            objs.append(json.loads(obj_str))
        except json.JSONDecodeError:
            # ignore it and move on
            pass
    return objs


def group_lines_by_hanging_indent(lines, mode='group'):
    """
    Group a series of lines into objects where parent lines are those which are less indented before it. Indents can be
    any white space character. Requires the first line to not be indented.

    Example:
    ```
    Parent1
        I am a child
        I am also a child
            I am a child of a child
        I am am just a child
    String without children
    Parent2
        Something
    ```

    `tree` Mode Will Yield:
    {
        'Parent1': {
            'I am a child': None,
            'I am also a child': {'I am a child of a child': None},
            'I am just a child': None
        },
        'String without children': None,
        'Parent2': {'Something': None}
    }

    `group` Mode Will Yield:
    [
        ['Parent1', 'I am a child', ['I am also a child', 'I am a child of a child'], 'I am just a child'],
        'String without children',
        ['Parent2', 'Something']
    ]

    :param lines: Union[str, List[str]]; String(s) to parse and group by hanging indents. If a single string it will
    break it up by lines.
    :param mode: str; Either `tree` or `group`, see above for examples.
    :return: any; Parsed and grouped data.
    """
    assert mode in ['group', 'tree']
    if isinstance(lines, str):
        lines = lines.splitlines()
    lines[0] = lines[0].lstrip()  # first line must not have any indentation

    if mode == 'group':
        obj = []
        _recursively_parse_lines_into_groups(lines, 0, obj, 0)
    elif mode == 'tree':
        _, obj = _recursively_parse_lines_into_tree(lines, 0, 0)
    else:
        assert False  # unreachable

    return obj


def _recursively_parse_lines_into_tree(lines, index, indent):
    obj = {}
    previous = None  # previous element so we can add children to it
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        cur_indent = len(line) - len(stripped)

        if cur_indent > indent:  # it is a child
            index, obj[previous] = _recursively_parse_lines_into_tree(lines, index, cur_indent)
        elif cur_indent == indent:  # it is a fellow member
            obj[stripped] = None
            previous = stripped
            index += 1
        else:  # it is not part of this sub group
            break
    return index, obj


def _recursively_parse_lines_into_groups(lines, index, obj, indent):
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        cur_indent = len(line) - len(stripped)

        if cur_indent > indent:  # it is a child
            obj[-1] = [obj[-1]]  # make a new group
            index = _recursively_parse_lines_into_groups(lines, index, obj[-1], cur_indent)
        elif cur_indent == indent:  # it is a fellow member
            obj.append(stripped)
            index += 1
        else:  # it is not part of this sub group
            break
    return index


def find_string_in_grouping(groups, pattern):
    """
    Searches for a string in an array structure of strings. Performs DFS.
    :param groups: Strings grouped by arrays with no bound on subgroups.
    :param pattern: str; The key string to search for; it is a regex search.
    :return: list[int]; Full index of the first match.
    """
    for (index, value) in enumerate(groups):
        assert isinstance(value, (list, str))
        if isinstance(value, str):
            if re.search(pattern, value):
                return [index]
        else:
            submatch = find_string_in_grouping(value, pattern)
            if submatch:
                index = [index]
                index.extend(submatch)
                return index
    return None


def parse_direction(direction):
    """
    Use this to standardize parsing the traffic direction strings.
    :param direction: str; The direction value to parse.
    :return: Optional[str]; One of 'ingress', 'egress', or 'both'. Returns None if it could not parse the value.
    """
    direction = direction.lower()
    if direction in {'ingress', 'incoming', 'inbound', 'in', 'i'}:
        return 'ingress'
    if direction in {'egress', 'outgoing', 'outbound', 'out', 'o'}:
        return 'egress'
    if direction in {'both', 'b', 'all', 'a'}:
        return 'both'
    return None
