"""
Global configuration for Monarch.
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
