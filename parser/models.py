from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    protocol: str

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: Optional[str] = None
