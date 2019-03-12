"""
Chaos toolkit interface for actions.
"""

from typing import Any, Dict, Optional, List
from chaoslib.types import Configuration
from monarch.ctk import run_ctk


def block_traffic(org: str, space: str, appname: str, configuration: Configuration, direction: str = 'ingress') ->\
        Dict[str, Any]:
    """
    Block all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param direction: str; Traffic direction to block.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.block(direction),
        configuration, org, space, appname,
        "Blocking {} traffic to {}...".format(direction, appname)
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


def block_services(org: str, space: str, appname: str, configuration: Configuration,
                   services: Optional[List[str]] = None, direction: str = 'egress') -> Dict[str, Any]:
    """
    Block the application from reaching all its services. (Blocks specific egress traffic).
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param services: List[String]; List of service names to block, will target all if unset.
    :param direction: String; Traffic direction to block.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.block_services(services=services, direction=direction),
        configuration, org, space, appname,
        "Blocking traffic to {} bound to {}...".format(services, appname) if services
        else "Blocking {} traffic to all services bound to {}...".format(direction, appname)
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


def block_service(org: str, space: str, appname: str, configuration: Configuration, service_name: str,
                  direction: str = 'egress') -> Dict[str, Any]:
    """
    Block the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param direction: String; Traffic direction to block.
    :return: A JSON Object representing the application which was targeted.
    """
    return block_services(org, space, appname,
                          configuration=configuration,
                          services=[service_name],
                          direction=direction)


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


def manipulate_network(org: str, space: str, appname: str, configuration: Configuration,
                       latency: int = None, latency_sd: int = None, loss: float = None, loss_r: float = None,
                       duplication: float = None, corruption: float = None):
    """
    Manipulate the network traffic from the application and its services. This will not work simultaneously with
    network shaping. (Manipulates egress traffic).

    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param latency: int; Latency to introduce in milliseconds.
    :param latency_sd: int; Standard deviation of the latency in milliseconds, if None, there will be no variance.
    With relatively large variance values, packet reordering will occur.
    :param loss: float; Percent in the range [0, 1] of packets which should be dropped/lost.
    :param loss_r: float; Correlation coefficient in the range [0, 1] of the packet loss.
    :param duplication: float; Percent in the range [0, 1] of packets which should be duplicated.
    :param corruption: float; Percent in the range [0, 1] of packets which should be corrupted.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.manipulate_network(
            latency=latency,
            latency_sd=latency_sd,
            loss=loss,
            loss_r=loss_r,
            duplication=duplication,
            corruption=corruption
        ),
        configuration, org, space, appname,
        "Manipulating network traffic to {}.".format(appname)
    )


def shape_network(org: str, space: str, appname: str, configuration: Configuration, upload_speed: int):
    """
    Impose bandwidth limits on the application's outgoing traffic. This will not work simultaneously with other
    network traffic manipulations and will also be undone by calling `unmanipulate_network`.

    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param upload_speed: The maximum upload speed in kilobits per second. (Must be >=10)
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.shape_network(upload_speed),
        configuration, org, space, appname,
        "Imposing bandwidth limits on {}.".format(appname)
    )


def unmanipulate_network(org: str, space: str, appname: str, configuration: Configuration):
    """
    Undo traffic manipulation changes to the application and its services.

    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.unmanipulate_network(),
        configuration, org, space, appname,
        "Removing alterations imposed on network traffic to {}.".format(appname)
    )


def kill_monit_process(org: str, space: str, appname: str, configuration: Configuration, process: str):
    """
    Kill a monit managed process on all diego cells the application is hosted on. Make sure to bring the process back
    up afterwords!

    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param process: str; Name of the monit job to kill.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.kill_monit_process(process),
        configuration, org, space, appname,
        "Killing monit process {}.".format(process)
    )


def start_monit_process(org: str, space: str, appname: str, configuration: Configuration, process: str):
    """
    Start a monit process on all diego cells the application is hosted on.

    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :param process: str; Name of the monit job to kill.
    :return: A JSON Object representing the application which was targeted.
    """
    return run_ctk(
        lambda app: app.start_monit_process(process),
        configuration, org, space, appname,
        "Starting monit process {}.".format(process)
    )
