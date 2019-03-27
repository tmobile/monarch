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
import sys

from monarch.util import *

GROUP_LINES_INPUT = """\
Parent1
    I am a child
    I am also a child
        I am a child of a child
    I am just a child
String without children
Parent2
    Something"""


def test_run_cmd():
    script = [
        "import sys",
        "print('Hello')",
        "print('world!', file=sys.stderr)",
        "exit(32)"
    ]

    rcode, stdout, stderr = run_cmd('python', stdin=script)
    assert rcode == 32
    assert stdout == 'Hello\n'
    assert stderr == 'world!\n'


def test_ping():
    # expected to fail on windows
    res = ping('localhost', count=20)
    assert res['stddev'] > 0
    assert res['min'] < res['avg'] < res['max']


def test_curl_ping():
    res = curl_ping('google.com', count=20)
    assert res['stddev'] > 0
    assert res['min'] < res['avg'] < res['max']
    assert res['min'] < res['median'] < res['max']


def test_extract_json():
    json_str = """some random output to throw out
    more garbage
    {"name":"John", "age":30,
      "cars": [
        "Ford",
        "BMW", "Fiat"
    ]}
    sdf
    { "name":"John",
                "age":30, "car":null
    }
    asdfasgdsf
    """

    objs = extract_json(json_str)
    obj1 = objs[0]
    obj2 = objs[1]
    assert obj1['name'] == obj2['name'] == 'John'
    assert obj1['age'] == obj2['age'] == 30
    assert obj2['car'] is None
    assert obj1['cars'] == ['Ford', 'BMW', 'Fiat']


def test_group_lines_by_hanging_indent_tree():
    expected = {
        'Parent1': {
            'I am a child': None,
            'I am also a child': {'I am a child of a child': None},
            'I am just a child': None
        },
        'String without children': None,
        'Parent2': {'Something': None}
    }

    tree = group_lines_by_hanging_indent(GROUP_LINES_INPUT, mode='tree')
    print(tree)
    assert tree == expected


def test_group_lines_by_hanging_indent_group():
    expected = [
        ['Parent1',
            'I am a child',
            ['I am also a child',
                'I am a child of a child'],
            'I am just a child'],
        'String without children',
        ['Parent2',
            'Something']
    ]

    groups = group_lines_by_hanging_indent(GROUP_LINES_INPUT, mode='group')
    print(groups)
    assert groups == expected


def test_find_string_in_grouping():
    groups = group_lines_by_hanging_indent(GROUP_LINES_INPUT, mode='group')
    assert find_string_in_grouping(groups, 'Parent2') == [2, 0]
    assert find_string_in_grouping(groups, 'String without children') == [1]
    assert find_string_in_grouping(groups, 'I am a child of a child') == [0, 2, 1]
    assert find_string_in_grouping(groups, 'Hello world') is None


def test_parse_direction():
    assert parse_direction('ingress') == 'ingress'
    assert parse_direction('egress') == 'egress'
    assert parse_direction('both') == 'both'

    assert parse_direction('in') == 'ingress'
    assert parse_direction('INGress') == 'ingress'
    assert parse_direction('Out') == 'egress'
    assert parse_direction('all') == 'both'


def test_filter_map():
    assert list(filter_map(lambda x: None if x % 2 == 1 else x // 2, range(10))) == [0, 1, 2, 3, 4]


def test_percent_diff():
    assert percent_diff(5, 10) == 2/3
    assert percent_diff(6, 4) == -0.4


def test_remove_outliers():
    assert remove_outliers([2, 2, 3, 3, 4, 5, 98]) == [2, 2, 3, 3, 4, 5]
    assert remove_outliers([3, 34, 40, 40, 40, 41, 100]) == [34, 40, 40, 40, 41]
    assert remove_outliers(range(10)) == list(range(10))
