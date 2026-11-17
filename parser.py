import struct
from typing import Optional, Tuple

class ParsedPacket:
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, seq: int, ack: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags
        self.seq = seq
        self.ack = ack

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02) and not bool(self.flags & 0x10)

    @property
    def is_syn_ack(self) -> bool:
        return bool(self.flags & 0x02) and bool(self.flags & 0x10)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & 0x10) and not bool(self.flags & 0x02)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_null(self) -> bool:
        return (self.flags & 0x3F) == 0

    @property
    def is_xmas(self) -> bool:
        return (self.flags & 0x29) == 0x29

class PacketParser:
    @staticmethod
    def parse_raw_ipv4_tcp(raw_bytes: bytes) -> Optional[ParsedPacket]:
        if len(raw_bytes) < 40:
            return None
        
        version_ihl = raw_bytes[0]
        version = version_ihl >> 4
        if version != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if len(raw_bytes) < ihl + 20:
            return None
        
        protocol = raw_bytes[9]
        if protocol != 6:
            return None
        
        src_ip = f"{raw_bytes[12]}.{raw_bytes[13]}.{raw_bytes[14]}.{raw_bytes[15]}"
        dst_ip = f"{raw_bytes[16]}.{raw_bytes[17]}.{raw_bytes[18]}.{raw_bytes[19]}"
        
        tcp_header = raw_bytes[ihl:ihl + 20]
        src_port, dst_port, seq, ack, offset_reserved, flags = struct.unpack("!HHIIBB", tcp_header[:14])
        
        return ParsedPacket(src_ip, dst_ip, src_port, dst_port, flags, seq, ack)
