import json
from subprocess import call, DEVNULL
from logzero import logger
from chaoslib.exceptions import FailedActivity


def cf_target(org, space, cfg):
    """
    Target a specific organization and space using the cloud foundry CLI. This should be run before anything which calls
    out to cloud foundry. This will fail if cloud foundry is not logged in.
    :param org: The organization to target.
    :param space: The space within the organization to target.
    :param cfg: Configuration information about the environment.
    :return: The returncode of the cloud foundry CLI.
    """
    cmd = '{} target -o {} -s {}'.format(cfg['cf']['cmd'], org, space)
    logger.debug('$ ' + cmd)
    return call(cmd.split(' '), stdout=DEVNULL, stderr=DEVNULL)


def extract_json(string):
    """
    Extract JSON from a string by scanning for the start `{` and end `}`. It will extract this from a string and then
    load it as a JSON object. If multiple json objects are detected, it will create a list of them. If no JSON is found,
    then None will be returned.
    :param string: String; String possibly containing one or more JSON objects.
    :return: Optional[list[dict[String, any]]]; A list of JSON objects or None.
    """
    depth = 0
    objstrs = []
    for index, char in enumerate(string):
        if char == '{':
            depth += 1

            if depth == 1:
                start = index
        elif char == '}' and depth > 0:
            depth -= 1

            if depth == 0:
                objstrs.append(string[start:index+1])

    if len(objstrs) <= 0:
        return None

    objs = []
    for s in objstrs:
        try:
            objs.append(json.loads(s))
        except json.JSONDecodeError:
            # ignore it and move on
            pass
    return objs


def run_ctk(f, msg=None):
    """
    This is a helper function to reduce code duplication when called by Chaos Toolkit.
    :param f: Fn[] -> App; A function which returns an App instance after performing some actions.
    :param msg: Optional[String]; A message to display at the beginning of operations.
    :return: Dict[String, Any]; The serialized App object after all operations were performed.
    """
    if msg:
        logger.info(msg)
    try:
        app = f()
    except SystemExit as e:
        logger.exception(e)
        raise FailedActivity(e)

    logger.info("Done!")
    return app.serialize(wrap=False)
