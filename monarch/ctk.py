"""
Chaos toolkit utility function(s).
"""

from chaoslib.exceptions import FailedActivity
from logzero import logger

from monarch.app import App
from monarch.config import Config


def run_ctk(func, cfg, org, space, appname, msg=None):
    """
    This is a helper function to reduce code duplication when called by Chaos Toolkit.
    :param func: Fn[app] -> Optional[any]; A function which performs some actions using an app object.
    :param cfg: Dict[String, any]; Configuration information about the environment.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param msg: Optional[String]; A message to display at the beginning of operations.
    :return: Dict[String, Any]; The serialized App object after all operations were performed.
    """
    if cfg:
        Config().load_dict(cfg)
    if msg:
        logger.info(msg)

    try:
        app = App.discover(org, space, appname)
        if not app:
            raise FailedActivity("Error discovering app!")
        result = func(app)
    except SystemExit as err:
        logger.exception(err)
        raise FailedActivity(err)

    if result:
        raise FailedActivity("Error performing operation! Function returned {}.".format(result))

    logger.info("Done!")
    return app.serialize()
