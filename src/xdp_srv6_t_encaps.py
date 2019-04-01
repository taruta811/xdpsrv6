import time
import ctypes
import socket
import ipaddress
from bcc import BPF

MAX_SEGMENTS = 5


class TransitBehaviorV4(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_uint32),
        ("segment_length", ctypes.c_uint32),
        ("saddr", ctypes.c_uint32 * 4),
        ("segments", ctypes.c_uint32 * (4 * MAX_SEGMENTS)),
    ]

    @staticmethod
    def create(mode, saddr, segments):
        tb = TransitBehaviorV4()

        tb.mode = mode
        tb.segment_length = len(segments)
        tb.set_saddr(ipaddress.IPv6Address(saddr))
        tb.set_segments(
            [ipaddress.IPv6Address(segment) for segment in segments])

        return tb

    def set_saddr(self, ipv6addr):
        addr_int = int(ipv6addr)
        for i in range(4):
            self.saddr[-i - 1] = socket.htonl(
                (addr_int >> (32 * i) & 0xffffffff))

    def set_segments(self, segments):
        for i, segment in enumerate(segments):
            addr_int = int(segment)
            for j in range(4):
                index = (3 - j) + 4 * i
                self.segments[index] = socket.htonl(
                    (addr_int >> (32 * j) & 0xffffffff))


def xdp_srv6_t_encap(device):
    bpf = BPF(src_file="./xdp_srv6_t_encaps.c")
    func = bpf.load_func("xdp_srv6_t_encaps", BPF.XDP)
    bpf.attach_xdp(device, func)

    tb_table = bpf.get_table("transit_table_v4")

    dst_ip_key = tb_table.Key(
        socket.htonl(int(ipaddress.IPv4Address(u"192.168.1.2"))))
    tb_table[dst_ip_key] = TransitBehaviorV4.create(
        mode=1, saddr=u"fc00::1", segments=[u"fc00::2"])

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break

    bpf.remove_xdp(device)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        exit(1)

    xdp_srv6_t_encap(sys.argv[1])
