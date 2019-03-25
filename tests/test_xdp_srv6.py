import unittest

from bcc import BPF, libbcc
import ctypes
from scapy.all import raw, Ether, ARP, IP, IPv6, TCP


class SRv6_T_Encaps_TestCase(unittest.TestCase):
    bpf = None
    func = None

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
            self.assertEqual(data_out[:size_out.value], raw(data_out_expect))

    def setUp(self):
        self.bpf = BPF(src_file=b"../src/xdp_srv6_t_encaps.c")
        self.func = self.bpf.load_func("xdp_srv6_t_encaps", BPF.XDP)

    def test_pass_arp(self):
        packet_in = Ether() / ARP()
        self._run_test(packet_in, None, BPF.XDP_PASS)

    def test_drop_unknown_ip(self):
        packet_in = Ether() / IP(
            src="192.168.0.1/24", dst="192.168.1.1/24") / TCP()
        self._run_test(packet_in, None, BPF.XDP_DROP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
