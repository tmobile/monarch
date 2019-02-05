import sys
import yaml
import json

from argparse import ArgumentParser
from logzero import logger
from monarch.app import App, discover_app
from monarch.util import cf_target

# Default path to the configuration file.
DEFAULT_CONFIG = 'config.yml'

# Record of past hosts and services we have targeted which allows us to undo our actions exactly as we had done them.
# This prevents lingering rules from existing if CF moves an app between the time it was blocked and unblocked.
DEFAULT_TARGETED = 'targeted.json'


def save_targeted(filename, app):
    """
    Save the targeted hosts to a JSON file. This allows for the same hosts that were blocked to be unblocked even if
    cloud foundry moves application instances to a different container or diego-cell.
    :param filename: String; Name of the file to save to.
    :param app: App; The application to save.
    """
    try:
        with open(filename, 'r') as file:
            j = json.load(file)
    except FileNotFoundError:
        j = {}

    app.serialize(obj=j)

    with open(filename, 'w') as file:
        json.dump(j, file, indent=2)


def load_targeted(filename, org, space, name):
    """
    Load a json file of known hosts and services. This allows for the same hosts that were blocked to be unblocked even
    if cloud foundry moves application instances to a different container or diego-cell. This will remove the entries
    for the specific app from the json file.
    :param filename: String; Name of the file to load from.
    :param org: String; Name of the organization the app is in within cloud foundry.
    :param space: String; Name of the space the app is in within cloud foundry.
    :param name: String; Name of the app within cloud foundry.
    :return: Optional[App]; The application with the org, space, and name or None if it was not present.
    """
    with open(filename, 'r') as file:
        j = json.load(file)

    app = App.deserialize(j, org, space, name, readonly=False)

    with open(filename, 'w') as file:
        # dump the json missing the hosts that we are unblocking
        json.dump(j, file, indent=2, sort_keys=True)

    return app


def main(*args):
    """
    The function which should be called if this is being used as an executable and not being imported as a library.
    It should also give an idea of what functions need to be called an in what order to block or unblock an application.
    """

    parser = ArgumentParser(description='Block Cloud Foundry Applications or their Services.')
    parser.add_argument('org', type=str,
                        help='Cloud Foundry Organization the Application is in.')
    parser.add_argument('space', type=str,
                        help='Cloud Foundry Space the Application is in.')
    parser.add_argument('app', type=str,
                        help='Name of the application in Cloud Foundry.')

    parser.add_argument('-b', '--block', dest='to_block', action='append', type=str,
                        help='Block access to a service.')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--block-app', dest='action', action='store_const', const='block_app',
                       help='Block access to the application.')
    group.add_argument('--block-services', dest='action', action='store_const', const='block_all_services',
                       help='Block the app from accessing any of its bound services.')
    group.add_argument('--unblock-all', dest='action', action='store_const', const='unblock',
                       help='Unblock the app and its services.')
    group.add_argument('--discover', dest='action', action='store_const', const='discover',
                       help='Discover the application hosts and bound service information.')

    parser.add_argument('--config', metavar='PATH', type=str, default=DEFAULT_CONFIG,
                        help='Specify an alternative config path.')
    parser.add_argument('--targeted', metavar='PATH', type=str, default=DEFAULT_TARGETED,
                        help='Specify an alternative storage location for targeted applications and services.')

    if args[0].endswith('.py'):
        args = args[1:]

    args = parser.parse_args(args)

    with open(args.config, 'r') as file:
        cfg = yaml.load(file)

    action = args.action or 'piecewise'
    org, space, appname = args.org, args.space, args.app

    if cf_target(org, space, cfg):
        logger.error("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                     .format(org, space))
        exit(1)

    if action == 'piecewise':
        to_block = args.to_block or []
        app = discover_app(cfg, org, space, appname)
        save_targeted(args.targeted, app)
        app.block_services(cfg, services=to_block)
    elif action == 'block_app':
        app = App(org, space, appname)
        app.find_hosts(cfg)
        save_targeted(args.targeted, app)
        app.block(cfg)
    elif action == 'unblock':
        app = load_targeted(args.targeted, org, space, appname)
        if app is None:
            exit(0)

        app.unblock(cfg)
        app.unblock_services(cfg)
    elif action == 'block_all_services':
        app = discover_app(cfg, org, space, appname)
        save_targeted(args.targeted, app)
        app.block_services(cfg)
    elif action == 'discover':
        app = discover_app(cfg, org, space, appname)

        print('\n---')  # add a newline
        yaml.dump(app.serialize(), stream=sys.stdout)
    else:
        # With argument parsing, this should never happen
        assert False

    print("\n=======\n Done!\n=======")


if __name__ == '__main__':
    try:
        main(*sys.argv)
    except SystemExit as e:
        if e.code:
            logger.exception(e)
            exit(1)
        else:
            exit(0)
