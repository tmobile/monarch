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

""" Global configuration for Monarch.
"""

import json
import yaml
from monarch.util import Singleton


class Config(dict, metaclass=Singleton):
    """
    Global configuration for Monarch. This is a singleton and only needs to have the values loaded once.
    """

    def load_yaml(self, path):
        """
        Load configuration from a yaml file.
        :param path: Path to configuration file.
        """
        with open(path) as file:
            self.load_dict(yaml.load(file))

    def load_json(self, path):
        """
        Load configuration from a json file.
        :param path: Path to configuration file.
        """
        with open(path) as file:
            self.load_dict(json.load(file))

    def load_dict(self, dictionary):
        """
        Load configuration from a dictionary.
        :param dictionary: Dictionary to read from.
        """
        for (key, value) in dictionary.items():
            self[key] = value
