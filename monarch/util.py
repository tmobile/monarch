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

""" Utilities to help reduce code duplication.
"""

import json
import re
import time
from statistics import median, variance, mean
from subprocess import Popen, PIPE
from logzero import logger
from socket import gethostbyname

from math import sqrt


def run_cmd(cmd, stdin=None, suppress_output=False, timeout=30):
    """
    Run a command in the shell.
    :param cmd: Union[str, List[str]]; Command to run.
    :param stdin: Optional[Union[str, List[str]]]; Input to pipe to the program.
    :param suppress_output: bool; If true, no extra debug output will be printed when an error occurs.
    :param timeout: int; How long to wait before timing out in seconds.
    :return: int, str, str; Returncode, stdout, stderr.
    """
    if isinstance(cmd, list):
        cmd = ' '.join(map(str, cmd))
    logger.debug('$ %s', cmd)

    if isinstance(stdin, list):
        for line in stdin:
            logger.debug('$> %s', line)
        stdin = '\n'.join(stdin)  # outer array of lines
    elif stdin:
        logger.debug('$> %s', stdin)

    try:
        with Popen(cmd, shell=True, stdin=(PIPE if stdin else None), stdout=PIPE, stderr=PIPE, encoding='utf8') as proc:
            if stdin:
                stdout, stderr = proc.communicate(input=stdin + '\n', timeout=120)
            else:
                proc.wait(timeout=timeout)
                stdout = proc.stdout.read()
                stderr = proc.stderr.read()
            rcode = proc.returncode
    except Exception as err:
        logger.warning(err)
        return 1, '', ''
    if rcode and not suppress_output:
        logger.warning("Command yielded non-zero return-code!")
        logger.debug("STDOUT:\n%s", stdout)
        logger.debug("STDERR:\n%s", stderr)
    # else:
    #     logger.debug("STDOUT:\n%s", stdout)
    #     logger.debug("STDERR:\n%s", stderr)
    return rcode, stdout, stderr


def ping(url, count=5, interval=200, size=None):
    """
    Ping a remote host. (Unix support only!)
    :param url: Location of the host to ping.
    :param count: Number of packets to send.
    :param interval: Time between packet sends in ms (200 is minimum allowed for non-root users).
    :param size: Size of the packet body to send in bytes. If not specified, then it will be an empty packet.
    :return: An object containing min, avg, max, and stddev of the round trip times in ms.
    """
    cmd = ['ping -c', count, '-i', interval / 1000]
    if size:
        cmd.extend(['-s', size])
    cmd.append(gethostbyname(url))
    rcode, stdout, _ = run_cmd(cmd)
    if rcode:
        raise RuntimeError("Failed to ping {}.".format(url))
    stdout = stdout.splitlines()[-1]
    match = re.match(r'rtt min/avg/max/mdev = ([.\d]+)/([.\d]+)/([.\d]+)/([.\d]+) ms', stdout)
    logger.debug('rtt min: %s, avg: %s, max: %s, stddev: %s', match[1], match[2], match[3], match[4])
    return {
        'min': float(match[1]),
        'avg': float(match[2]),
        'max': float(match[3]),
        'stddev': float(match[4])
    }


def curl_ping(url, count=5):
    """
    Call a remote host directly using curl. Will calculate the amount of time taken to get the values from the server.
    :param url: Location of the host to ping.
    :param count: Number of requests to make.
    :return: An object containing min, avg, max, and stddev of the round trip times in ms.
    """
    cmd = ['curl', url]
    times = []
    for _ in range(count):
        time_start = time.time() * 1000
        rcode, _, _ = run_cmd(cmd)
        time_stop = time.time() * 1000
        if rcode:
            raise RuntimeError('Failed to curl {}'.format(url))
        duration = time_stop - time_start
        times.append(duration)
        logger.debug('rtt %fms', duration)

    stats = {
        'min': min(times),
        'avg': mean(times),
        'max': max(times),
        'median': median(times),
        'stddev': sqrt(variance(times)),
        'times': times
    }
    return stats


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
        I am just a child
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
        ['Parent1',
            'I am a child',
            ['I am also a child',
                'I am a child of a child'],
            'I am just a child'],
        'String without children',
        ['Parent2',
            'Something']
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
    else:
        _, obj = _recursively_parse_lines_into_tree(lines, 0, 0)

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


def filter_map(func, iterable):
    """
    Standard filter map iterator. Filters anything which is mapped to None.
    """
    return filter(
        lambda i: i is not None,
        map(func, iterable)
    )


def percent_diff(a, b):
    """
    Calculate the percent by which `b` deviates from `a`.
    :param a: First value. (Traditionally the initial value).
    :param b: Second value. (Traditionally the final value).
    :return: Percent by which `b` deviates from `a`. (Positive iff b >= a)
    """
    return (b - a) / ((a + b) / 2)


def remove_outliers(values):
    """
    Return the list of values without any outliers.
    :param values: Iterable series of numbers.
    :return: `values` without outliers defined by being outside 1.5 times the IQR.
    """
    values = list(values)
    values.sort()
    count = len(values)

    q1 = median(values[:count//2])
    q3 = median(values[count//2+1:])
    iqr = q3 - q1
    min_v = q1 - 1.5 * iqr
    max_v = q3 + 1.5 * iqr
    return list(filter(lambda v: min_v <= v <= max_v, values))


def smart_average(values):
    """
    Compute the mean of a series of values after removing outliers based on IQR.
    :param values: Iterable series of numbers.
    :return: Average of values after excluding outliers.
    """
    return mean(remove_outliers(values))


class Singleton(type):
    """
    Basic singleton type
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Override the type 'call'.  If no _instance, or if _instance is
        empty then raise error.  Handler instantiates the object.  We
        check for the existence of the variable to facilitate teardown
        during testing.
        """
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]
