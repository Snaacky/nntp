from __future__ import annotations

import datetime
import socket
import ssl
from email.header import decode_header as _email_decode_header
from typing import Any

from nntp._constants import _DEFAULT_OVERVIEW_FMT, _OVERVIEW_FMT_ALTERNATIVES
from nntp._exceptions import NNTPDataError


# Helper function(s)
def decode_header(header_str: str) -> str:
    """Takes a unicode string representing a munged header value
    and decodes it as a (possibly non-ASCII) readable value."""
    parts = []
    for v, enc in _email_decode_header(header_str):
        if isinstance(v, bytes):
            parts.append(v.decode(enc or "ascii"))
        else:
            parts.append(v)
    return "".join(parts)


def _parse_overview_fmt(lines: list[str]) -> list[str]:
    """Parse a list of string representing the response to LIST OVERVIEW.FMT
    and return a list of header/metadata names.
    Raises NNTPDataError if the response is not compliant
    (cf. RFC 3977, section 8.4)."""
    fmt = []
    for line in lines:
        if line[0] == ":":
            # Metadata name (e.g. ":bytes")
            name, _, suffix = line[1:].partition(":")
            name = ":" + name
        else:
            # Header name (e.g. "Subject:" or "Xref:full")
            name, _, suffix = line.partition(":")
        name = name.lower()
        name = _OVERVIEW_FMT_ALTERNATIVES.get(name, name)
        # Should we do something with the suffix?
        fmt.append(name)
    defaults = _DEFAULT_OVERVIEW_FMT
    if len(fmt) < len(defaults):
        raise NNTPDataError("LIST OVERVIEW.FMT response too short")
    if fmt[: len(defaults)] != defaults:
        raise NNTPDataError("LIST OVERVIEW.FMT redefines default fields")
    return fmt


def _parse_overview(lines: list[str], fmt: list[str]) -> list[tuple[int, dict[str, Any]]]:
    """Parse the response to an OVER or XOVER command according to the
    overview format `fmt`."""
    n_defaults = len(_DEFAULT_OVERVIEW_FMT)
    overview = []
    for line in lines:
        fields = {}
        article_number, *tokens = line.split("\t")
        article_number = int(article_number)
        for i, token in enumerate(tokens):
            if i >= len(fmt):
                # XXX should we raise an error? Some servers might not
                # support LIST OVERVIEW.FMT and still return additional
                # headers.
                continue
            field_name = fmt[i]
            is_metadata = field_name.startswith(":")
            if i >= n_defaults and not is_metadata:
                # Non-default header names are included in full in the response
                # (unless the field is totally empty)
                h = field_name + ": "
                if token and token[: len(h)].lower() != h:
                    raise NNTPDataError("OVER/XOVER response doesn't include " "names of additional headers")
                token = token[len(h) :] if token else None
            fields[fmt[i]] = token
        overview.append((article_number, fields))
    return overview


def _parse_datetime(date_str: str, time_str: str | None = None) -> datetime.datetime:
    """Parse a pair of (date, time) strings, and return a datetime object.
    If only the date is given, it is assumed to be date and time
    concatenated together (e.g. response to the DATE command).
    """
    if time_str is None:
        time_str = date_str[-6:]
        date_str = date_str[:-6]
    hours = int(time_str[:2])
    minutes = int(time_str[2:4])
    seconds = int(time_str[4:])
    year = int(date_str[:-4])
    month = int(date_str[-4:-2])
    day = int(date_str[-2:])
    # RFC 3977 doesn't say how to interpret 2-char years.  Assume that
    # there are no dates before 1970 on Usenet.
    if year < 70:
        year += 2000
    elif year < 100:
        year += 1900
    return datetime.datetime(year, month, day, hours, minutes, seconds)


def _unparse_datetime(dt: datetime.datetime, legacy: bool = False) -> tuple[str, str]:
    """Format a date or datetime object as a pair of (date, time) strings
    in the format required by the NEWNEWS and NEWGROUPS commands.  If a
    date object is passed, the time is assumed to be midnight (00h00).

    The returned representation depends on the legacy flag:
    * if legacy is False (the default):
      date has the YYYYMMDD format and time the HHMMSS format
    * if legacy is True:
      date has the YYMMDD format and time the HHMMSS format.
    RFC 3977 compliant servers should understand both formats; therefore,
    legacy is only needed when talking to old servers.
    """
    if not isinstance(dt, datetime.datetime):
        time_str = "000000"
    else:
        time_str = "{0.hour:02d}{0.minute:02d}{0.second:02d}".format(dt)
    y = dt.year
    if legacy:
        y = y % 100
        date_str = "{0:02d}{1.month:02d}{1.day:02d}".format(y, dt)
    else:
        date_str = "{0:04d}{1.month:02d}{1.day:02d}".format(y, dt)
    return date_str, time_str


def _encrypt_on(sock: socket.socket, context: ssl.SSLContext, hostname: str) -> ssl.SSLSocket:
    """Wrap a socket in SSL/TLS. Arguments:
    - sock: Socket to wrap
    - context: SSL context to use for the encrypted connection
    Returns:
    - sock: New, encrypted socket.
    """
    # Generate a default SSL context if none was passed.
    if context is None:
        context = ssl._create_stdlib_context()
    return context.wrap_socket(sock, server_hostname=hostname)
