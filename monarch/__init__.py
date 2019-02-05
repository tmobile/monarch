"""Top-level package for chaostoolkit-cf-appblocker."""

__version__ = '0.1.0'


# Default encoding we assume all pipes should use
DEFAULT_ENCODING = 'UTF-8'

# Number of times we should remove the iptables rule we added to block an app. This should be greater than one in case
# you accident run this script to block it more than once before unblocking it.
TIMES_TO_REMOVE = 6
