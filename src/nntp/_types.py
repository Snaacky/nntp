from typing_extensions import IO, NamedTuple, TypeAlias, Union

File: TypeAlias = Union[IO[bytes], bytes, str, None]


class GroupInfo(NamedTuple):
    group: str
    last: str
    first: str
    flag: str


class ArticleInfo(NamedTuple):
    number: int
    message_id: str
    lines: list[bytes]
