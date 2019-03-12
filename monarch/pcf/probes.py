"""
Chaos toolkit interface for probes.
"""

from typing import Any, Dict
from chaoslib.types import Configuration
from monarch.ctk import run_ctk


def discover_app(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Find application instances of this application in Cloud Foundry and any bound services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: None,  # Noop because it's already discovered
        configuration, org, space, appname
    )
