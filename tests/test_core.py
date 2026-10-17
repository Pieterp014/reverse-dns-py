import unittest
from unittest import mock

import socket

from reverse_dns_py.core import ReverseDNSResolver, PTRResult, DNSError


class FakeGAIError(socket.gaierror):
    pass


class FakeHerr(socket.herror):
    pass


class ResolveNormaliseTests(unittest.TestCase):
    """Ensure we canonicalise input addresses before any lookup."""

    def test_ipv4_normalised_to_canonical_form(self):
        # `gethostbyaddr` is patched, so this only exercises normalisation.
        with mock.patch("socket.gethostbyaddr", return_value=("host.test", [], [])):
            r = ReverseDNSResolver().resolve("192.168.001.001")
        self.assertEqual(r.ip, "192.168.1.1")

    def test_ipv6_normalised_to_compressed_form(self):
        with mock.patch("socket.gethostbyaddr", return_value=("host.test", [], [])):
            r = ReverseDNSResolver().resolve("0:0:0:0:0:0:0:1")
        self.assertEqual(r.ip, "::1")

    def test_malformed_ip_raises_value_error(self):
        with self.assertRaises(ValueError):
            ReverseDNSResolver().resolve("not-an-ip")


class PTRResultTests(unittest.TestCase):
    def test_no_ptr_yields_unconfirmed_none(self):
        with mock.patch("socket.gethostbyaddr", side_effect=socket.gaierror("no PTR")):
            r = ReverseDNSResolver().resolve("203.0.113.5")
        self.assertEqual(r.ptr, None)
        self.assertFalse(r.confirmed)

    def test_herror_treated_as_no_ptr(self):
        # Some platforms raise herror for host-not-found; we treat it identically
        # to gaierror so callers don't have to catch both.
        with mock.patch("socket.gethostbyaddr", side_effect=socket.herror("no host")):
            r = ReverseDNSResolver().resolve("203.0.113.6")
        self.assertIsNone(r.ptr)
        self.assertFalse(r.confirmed)

    def test_ptr_with_matching_forward_is_confirmed(self):
        with mock.patch("socket.gethostbyaddr", return_value=("good.test", [], [])):
            with mock.patch(
                "socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.7", 0))
                ],
            ):
                r = ReverseDNSResolver().resolve("203.0.113.7")
        self.assertEqual(r.ptr, "good.test")
        self.assertTrue(r.confirmed)

    def test_ipv6_ptr_confirmed_with_matching_aaaa(self):
        with mock.patch("socket.gethostbyaddr", return_value=("v6.test", [], [])):
            with mock.patch(
                "socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))
                ],
            ):
                r = ReverseDNSResolver().resolve("::1")
        self.assertEqual(r.ptr, "v6.test")
        self.assertTrue(r.confirmed)

    def test_ptr_without_forward_is_unconfirmed(self):
        with mock.patch("socket.gethostbyaddr", return_value=("bad.test", [], [])):
            with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("no A")):
                r = ReverseDNSResolver().resolve("203.0.113.8")
        self.assertEqual(r.ptr, "bad.test")
        self.assertFalse(r.confirmed)

    def test_ptr_with_mismatched_forward_is_unconfirmed(self):
        # Forward lookup returns a different address → spoofed PTR.
        with mock.patch("socket.gethostbyaddr", return_value=("spoof.test", [], [])):
            with mock.patch(
                "socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("198.51.100.1", 0))
                ],
            ):
                r = ReverseDNSResolver().resolve("203.0.113.9")
        self.assertEqual(r.ptr, "spoof.test")
        self.assertFalse(r.confirmed)

    def test_forward_addresses_normalised_before_comparison(self):
        # Forward lookup returns `0:0:0:0:0:0:0:1`; input was `::1`. They must
        # compare equal after normalisation.
        with mock.patch("socket.gethostbyaddr", return_value=("n6.test", [], [])):
            with mock.patch(
                "socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("0:0:0:0:0:0:0:1", 0, 0, 0))
                ],
            ):
                r = ReverseDNSResolver().resolve("::1")
        self.assertTrue(r.confirmed)


class ResultShapeTests(unittest.TestCase):
    def test_returns_ptrresult_instance(self):
        with mock.patch("socket.gethostbyaddr", side_effect=socket.gaierror("x")):
            r = ReverseDNSResolver().resolve("203.0.113.10")
        self.assertIsInstance(r, PTRResult)
        self.assertEqual(r, PTRResult(ip="203.0.113.10", ptr=None, confirmed=False))


class UnexpectedErrorTests(unittest.TestCase):
    def test_unexpected_oserror_propagates_as_dnserror(self):
        with mock.patch("socket.gethostbyaddr", side_effect=OSError("boom")):
            with self.assertRaises(DNSError):
                ReverseDNSResolver().resolve("203.0.113.11")


if __name__ == "__main__":
    unittest.main()
