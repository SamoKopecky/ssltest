from typing import NamedTuple


class SocketAddress(NamedTuple):
    url: str
    port: int
