import unittest

from bcc import BPF, libbcc
import ctypes
from scapy.all import raw, Ether, ARP, IP, IPv6, TCP, IPv6ExtHdrSegmentRouting
import ipaddress
import socket

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


class SRv6_T_Encaps_TestCase(unittest.TestCase):
    bpf = None
    func = None
    tb_table = None

    DATA_OUT_LEN = 1514

    def _run_test(self, data, data_out_expect, retval_expect, repeat=1):
        size = len(data)
        data = ctypes.create_string_buffer(raw(data), size)
        data_out = ctypes.create_string_buffer(self.DATA_OUT_LEN)
        size_out = ctypes.c_uint32()
        retval = ctypes.c_uint32()
        duration = ctypes.c_uint32()

        ret = libbcc.lib.bpf_prog_test_run(self.func.fd, repeat,
                                           ctypes.byref(data), size,
                                           ctypes.byref(data_out),
                                           ctypes.byref(size_out),
                                           ctypes.byref(retval),
                                           ctypes.byref(duration))
        self.assertEqual(ret, 0)

        self.assertEqual(retval.value, retval_expect)
        if data_out_expect:
            # print("")
            # print("real: {}".format(data_out[:size_out.value].encode("hex")))
            # print("exp:  {}".format(raw(data_out_expect).encode("hex")))
            self.assertEqual(data_out[:size_out.value], raw(data_out_expect))

    def setUp(self):
        self.bpf = BPF(src_file=b"../src/xdp_srv6_t_encaps.c")
        self.func = self.bpf.load_func("xdp_srv6_t_encaps", BPF.XDP)

        self.tb_table = self.bpf.get_table("transit_table_v4")

        dst_ip_key = self.tb_table.Key(
            socket.htonl(int(ipaddress.IPv4Address(u"192.168.1.2"))))
        self.tb_table[dst_ip_key] = TransitBehaviorV4.create(
            mode=1, saddr=u"fc00::1", segments=[u"fc00::2"])

        dst_ip_key = self.tb_table.Key(
            socket.htonl(int(ipaddress.IPv4Address(u"192.168.1.3"))))
        self.tb_table[dst_ip_key] = TransitBehaviorV4.create(
            mode=1, saddr=u"fc00::1", segments=[u"fc00::2", u"fc00::3"])

    def test_pass_arp(self):
        packet_in = Ether() / ARP()
        self._run_test(packet_in, None, BPF.XDP_PASS)

    def test_pass_ipv4_unknown_address(self):
        packet_in = Ether() / IP(src="192.168.0.1", dst="192.168.0.2") / TCP()
        self._run_test(packet_in, None, BPF.XDP_PASS)

    def test_encap__ipv4_one_segment(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IP(src="192.168.1.1", dst="192.168.1.2") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::2") / \
            IPv6ExtHdrSegmentRouting(len=(8 + 16 * 1), segleft=1, lastentry=1, addresses=["fc00::2"]) / \
            IP(src="192.168.1.1", dst="192.168.1.2") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)

    def test_encap_ipv4_two_segments(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::3") / \
            IPv6ExtHdrSegmentRouting(len=(8 + 16 * 2), segleft=2, lastentry=2, addresses=["fc00::2", "fc00::3"]) / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)


if __name__ == "__main__":
    unittest.main(verbosity=2)
