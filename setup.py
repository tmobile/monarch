#!/usr/bin/env python

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

""" Monarch builder and installer.
"""

import io

from setuptools import setup
from monarch import __version__

name = 'monarch'
desc = 'Chaos Toolkit Extension for Targeted Experiments on Cloud Foundry Apps and Services'

with io.open('README.md', encoding='utf-8') as strm:
    long_desc = strm.read()

classifiers = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Operating System :: OS Independent',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: Implementation'
]
author = "Matthew Conover"
packages = ['monarch']

install_require = []
with io.open('requirements.txt') as f:
    install_require = [l.strip() for l in f if not l.startswith('#')]

setup_params = dict(
    name=name,
    version=__version__,
    description=desc,
    long_description=long_desc,
    classifiers=classifiers,
    author=author,
    packages=packages,
    include_package_data=True,
    setup_requires=['pytest_runner'],
    tests_require=['pytest'],
    install_requires=install_require,
    python_requires='>=3.5.*'
)


def main():
    """Package installation entry point."""
    setup(**setup_params)


if __name__ == '__main__':
    main()
