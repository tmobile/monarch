"""
Chaos toolkit interface for actions.
"""

from typing import Any, Dict
from chaoslib.types import Configuration
from monarch.ctk import run_ctk


def block_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Block all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.block(),
        configuration, org, space, appname,
        "Blocking all traffic to {}...".format(appname)
    )


def unblock_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Unblock all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.unblock(),
        configuration, org, space, appname,
        "Unblocking all traffic to {}...".format(appname)
    )


def crash_random_instance(org: str, space: str, appname: str, configuration: Configuration, count: int = 1):
    """
    Crash one or more random application instances.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param count: int; Number of instances to kill.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.crash_random_instance(count=count),
        configuration, org, space, appname,
        "Crashing {} random app instance(s)...".format(count)
    )


def block_services(org: str, space: str, appname: str, configuration: Configuration, services=None) -> Dict[str, Any]:
    """
    Block the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param services: List[String]; List of service names to block, will target all if unset.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.block_services(services=services),
        configuration, org, space, appname,
        "Blocking traffic to {} bound to {}...".format(services, appname) if services
        else "Blocking traffic to all services bound to {}...".format(appname)
    )


def unblock_services(org: str, space: str, appname: str, configuration: Configuration, services=None) -> Dict[str, Any]:
    """
    Unblock the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param services: List[String]; List of service names to unblock, will target all if unset.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.unblock_services(services=services),
        configuration, org, space, appname,
        "Unblocking traffic to {} bound to {}...".format(services, appname) if services
        else "Unblocking traffic to all services bound to {}...".format(appname)
    )


def block_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) ->\
        Dict[str, Any]:
    """
    Block the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return block_services(org, space, appname, services=[service_name], configuration=configuration)


def unblock_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) ->\
        Dict[str, Any]:
    """
    Unblock the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return unblock_services(org, space, appname, services=[service_name], configuration=configuration)
