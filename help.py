import logging
import re
from datetime import datetime, timezone

# regular expression that detects ANSI color codes
from tqdm import tqdm

ansi_escape_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', re.VERBOSE)


def _strip_ansi_codes(message: str) -> str:
    """
    Strip ANSI sequences from a log string
    """
    return ansi_escape_regex.sub('', message)


def datetime_to_epoch_millis(date: datetime) -> int:
    """
    Convert a datetime object to an epoch timestamp in milliseconds.
    """
    return int((date - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1000)