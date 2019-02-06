from chaoslib.types import Configuration
from typing import Any, Dict

from monarch.app import App, discover_app
from monarch.util import run_ctk as _run


def block_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Block all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(configuration)
        app.block(configuration)
        if configuration.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        return app

    return _run(f, "Blocking all traffic to {}...".format(appname))


def unblock_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Unblock all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        if configuration.get('database'):
            # TODO: Implement reading from a DB what we last targeted
            assert False
        else:
            app = App(org, space, appname)
            app.find_hosts(configuration)

        app.unblock(configuration)
        return app

    return _run(f, "Unblocking all traffic to {}...".format(appname))


def crash_random_instance(org: str, space: str, appname: str, configuration: Configuration, count: int=1):
    """
    Crash one or more random application instances.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param count: int; Number of instances to kill.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = discover_app(configuration, org, space, appname)
        app.crash_random_instance(configuration, count=count)
        return app

    msg = 'Crashing {} random app instance(s)...'.format(count)
    return _run(f, msg)


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
    def f():
        app = discover_app(configuration, org, space, appname)
        if configuration.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        app.block_services(configuration, services=services)
        return app

    msg = "Blocking traffic to {} bound to {}...".format(services, appname) if services \
        else "Blocking traffic to all services bound to {}...".format(appname)
    return _run(f, msg)


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
    def f():
        if configuration.get('database'):
            # TODO: Implement reading from a DB what we targeted
            assert False
        else:
            app = discover_app(configuration, org, space, appname)
        app.unblock_services(configuration, services=services)
        return app

    msg = "Unblocking traffic to {} bound to {}...".format(services, appname) if services \
        else "Unblocking traffic to all services bound to {}...".format(appname)
    return _run(f, msg)


def block_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) -> Dict[str, Any]:
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


def unblock_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) -> Dict[str, Any]:
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
