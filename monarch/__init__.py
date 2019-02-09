"""Top-level package for monarch."""

__version__ = '0.1.0'


# Number of times we should remove the iptables rule we added to block an app. This should be greater than one in case
# you accidentally run this script to block it more than once before unblocking it.
TIMES_TO_REMOVE = 6
