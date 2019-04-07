import unittest

from enum import IntEnum
from bcc import BPF, libbcc
import ctypes
from scapy.all import raw, Ether, ARP, IP, IPv6, TCP, IPv6ExtHdrSegmentRouting
import ipaddress
import socket

MAX_SEGMENTS = 5


class SRv6EndFunction(IntEnum):
    END = 1
    END_X = 2
    END_T = 3
    END_DX2 = 4
    END_DX6 = 5
    END_DX4 = 6
    END_DT6 = 7
    END_DT4 = 8
    END_B6 = 9
    END_B6_ENCAPS = 10
    END_BM = 11
    END_S = 12
    END_AS = 13
    END_AM = 14


def ipv6_to_n(ipv6):
    addr = (ctypes.c_uint32 * 4)()
    addr_int = int(ipv6)
    for i in range(4):
        addr[-i - 1] = socket.htonl((addr_int >> (32 * i) & 0xffffffff))
    return addr


class EndFunction(ctypes.Structure):
    _fields_ = [
        ("function", ctypes.c_uint8),
    ]

    @staticmethod
    def create(function):
        ef = EndFunction()
        ef.function = function
        return ef


class TransitBehavior(ctypes.Structure):
    _fields_ = [
        ("segment_length", ctypes.c_uint32),
        ("saddr", ctypes.c_uint32 * 4),
        ("segments", (ctypes.c_uint32 * 4) * MAX_SEGMENTS),
    ]

    @staticmethod
    def create(saddr, segments):
        tb = TransitBehavior()

        tb.segment_length = len(segments)
        tb.set_saddr(ipaddress.IPv6Address(saddr))
        tb.set_segments(
            [ipaddress.IPv6Address(segment) for segment in segments])

        return tb

    def set_saddr(self, ipv6addr):
        self.saddr = ipv6_to_n(ipv6addr)

    def set_segments(self, segments):
        for i, segment in enumerate(segments):
            self.segments[i] = ipv6_to_n(segment)


class SRv6TestCaseBase(unittest.TestCase):
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


class SRv6_T_Encaps_TestCase(SRv6TestCaseBase):
    def setUp(self):
        self.bpf = BPF(src_file=b"../src/xdp_srv6_t_encaps.c")
        self.func = self.bpf.load_func("xdp_srv6_t_encaps", BPF.XDP)

        self.tb_table_v4 = self.bpf.get_table("transit_table_v4")
        self.tb_table_v6 = self.bpf.get_table("transit_table_v6")

        # IPv4 encap rule (one segment)
        dst_ip_key = self.tb_table_v4.Key(
            socket.htonl(int(ipaddress.IPv4Address(u"192.168.1.2"))))
        self.tb_table_v4[dst_ip_key] = TransitBehavior.create(
            saddr=u"fc00::1", segments=[u"fc00::2"])

        # IPv4 encap rule (two segments)
        dst_ip_key = self.tb_table_v4.Key(
            socket.htonl(int(ipaddress.IPv4Address(u"192.168.1.3"))))
        self.tb_table_v4[dst_ip_key] = TransitBehavior.create(
            saddr=u"fc00::1", segments=[u"fc00::2", u"fc00::3"])

        # IPv6 encap rule (one segment)
        dst_ip_key = self.tb_table_v6.Key()
        dst_ip_key.in6_u.u6_addr32 = ipv6_to_n(
            ipaddress.IPv6Address(u"2001:db8::2"))
        self.tb_table_v6[dst_ip_key] = TransitBehavior.create(
            saddr=u"fc00::1", segments=[u"fc00::2"])

        # IPv6 encap rule (two segments)
        dst_ip_key = self.tb_table_v6.Key()
        dst_ip_key.in6_u.u6_addr32 = ipv6_to_n(
            ipaddress.IPv6Address(u"2001:db8::3"))
        self.tb_table_v6[dst_ip_key] = TransitBehavior.create(
            saddr=u"fc00::1", segments=[u"fc00::2", u"fc00::3"])

    def test_pass_arp(self):
        packet_in = Ether() / ARP()
        self._run_test(packet_in, None, BPF.XDP_PASS)

    def test_pass_ipv4_unknown_address(self):
        packet_in = Ether() / IP(src="192.168.0.1", dst="192.168.0.2") / TCP()
        self._run_test(packet_in, None, BPF.XDP_PASS)

    def test_encap_ipv4_one_segment(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IP(src="192.168.1.1", dst="192.168.1.2") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::2") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 1) / 8, segleft=0, lastentry=0, addresses=["fc00::2"]) / \
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
            IPv6ExtHdrSegmentRouting(len=(16 * 2) / 8, segleft=1, lastentry=1, addresses=["fc00::2", "fc00::3"]) / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)

    def test_encap_ipv6_one_segment(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IPv6(src="2001:db8::1", dst="2001:db8::2") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::2") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 1) / 8, segleft=0, lastentry=0, addresses=["fc00::2"]) / \
            IPv6(src="2001:db8::1", dst="2001:db8::2") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)

    def test_encap_ipv6_two_segment(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IPv6(src="2001:db8::1", dst="2001:db8::3") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::3") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 2) / 8, segleft=1, lastentry=1, addresses=["fc00::2", "fc00::3"]) / \
            IPv6(src="2001:db8::1", dst="2001:db8::3") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)


class SRv6_End_TestCase(SRv6TestCaseBase):
    def setUp(self):
        self.bpf = BPF(src_file=b"../src/xdp_srv6_end_functions.c")
        self.func = self.bpf.load_func("xdp_srv6_handle_end_function", BPF.XDP)

        self.end_function_table = self.bpf.get_table("end_function_table")

        dst_ip_key = self.end_function_table.Key()
        dst_ip_key.in6_u.u6_addr32 = ipv6_to_n(
            ipaddress.IPv6Address(u"fc00::3"))
        self.end_function_table[dst_ip_key] = EndFunction.create(
            function=SRv6EndFunction.END)

    def test_end_ipv4_valid(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IPv6(src="fc00::1", dst="fc00::3") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 2) / 8, segleft=1, lastentry=1, addresses=["fc00::2", "fc00::3"]) / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        packet_out = \
            Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
            IPv6(src="fc00::1", dst="fc00::2") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 2) / 8, segleft=0, lastentry=1, addresses=["fc00::2", "fc00::3"]) / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        self._run_test(packet_in, packet_out, BPF.XDP_TX)

    def test_end_ipv4_segment_left_zero(self):
        packet_in = \
            Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
            IPv6(src="fc00::1", dst="fc00::3") / \
            IPv6ExtHdrSegmentRouting(len=(16 * 2) / 8, segleft=0, lastentry=0, addresses=["fc00::3"]) / \
            IP(src="192.168.1.1", dst="192.168.1.3") / \
            TCP()
        self._run_test(packet_in, None, BPF.XDP_DROP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
