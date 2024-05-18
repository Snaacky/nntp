from __future__ import annotations

# maximal line length when calling readline(). This is to prevent
# reading arbitrary length lines. RFC 3977 limits NNTP line length to
# 512 characters, including CRLF. We have selected 2048 just to be on
# the safe side.
_MAXLINE = 2048

# Standard port used by NNTP servers
NNTP_PORT = 119
NNTP_SSL_PORT = 563

# Response numbers that are followed by additional text (e.g. article)
_LONGRESP = {
    "100",  # HELP
    "101",  # CAPABILITIES
    "211",  # LISTGROUP   (also not multi-line with GROUP)
    "215",  # LIST
    "220",  # ARTICLE
    "221",  # HEAD, XHDR
    "222",  # BODY
    "224",  # OVER, XOVER
    "225",  # HDR
    "230",  # NEWNEWS
    "231",  # NEWGROUPS
    "282",  # XGTITLE
}

# Default decoded value for LIST OVERVIEW.FMT if not supported
_DEFAULT_OVERVIEW_FMT = [
    "subject",
    "from",
    "date",
    "message-id",
    "references",
    ":bytes",
    ":lines",
]

# Alternative names allowed in LIST OVERVIEW.FMT response
_OVERVIEW_FMT_ALTERNATIVES = {
    "bytes": ":bytes",
    "lines": ":lines",
}

# Line terminators (we always output CRLF, but accept any of CRLF, CR, LF)
_CRLF = b"\r\n"
