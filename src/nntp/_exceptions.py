from __future__ import annotations


# Exceptions raised when an error or invalid response is received
class NNTPError(Exception):
    """Base class for all nntp exceptions"""

    def __init__(self, *args: str) -> None:
        Exception.__init__(self, *args)
        try:
            self.response = args[0]
        except IndexError:
            self.response = "No response given"


class NNTPReplyError(NNTPError):
    """Unexpected [123]xx reply"""


class NNTPTemporaryError(NNTPError):
    """4xx errors"""


class NNTPPermanentError(NNTPError):
    """5xx errors"""


class NNTPProtocolError(NNTPError):
    """Response does not begin with [1-5]"""


class NNTPDataError(NNTPError):
    """Error in response data"""
