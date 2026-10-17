"""Core reverse DNS resolver with forward-confirmation of PTR records.

Design decisions
----------------
This module uses the system resolver via :mod:`socket` for the PTR lookup and
then performs a forward lookup on the returned hostname to confirm that the
PTR is not spoofed. We deliberately do **not** use ``dnspython`` or any other
third-party library so that the package and its test suite run in a sandbox
with no network access and no install step.

The trickiest design choice is how to confirm a PTR. A PTR record maps an IP
to a name, but an attacker can set *any* name in their own PTR. To trust the
name we perform a forward lookup (A/AAAA) on that name and accept it only if
the original IP is among the returned addresses. If the forward lookup fails
or does not include the original IP, ``confirmed`` is ``False``.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional, Tuple, List


class DNSError(Exception):
    """Raised when an underlying socket lookup fails with an unexpected error."""


@dataclass(frozen=True)
class PTRResult:
    """Outcome of a reverse DNS lookup.

    Attributes
    ----------
    ip:
        The address that was looked up (normalised string form).
    ptr:
        The hostname returned by the PTR query, or ``None`` if no PTR exists.
    confirmed:
        ``True`` only when a forward lookup of ``ptr`` contains ``ip``.
    """

    ip: str
    ptr: Optional[str]
    confirmed: bool


def _normalise_ip(ip: str) -> str:
    """Normalise an IP string to its canonical compressed form.

    Raising ``ValueError`` here lets the caller catch bad input before any
    network call, and the message is preserved in :meth:`ReverseDNSResolver.resolve`.
    """
    # The ``ipaddress`` module in the standard library refuses leading-zero
    # octets such as ``192.168.001.001`` (RFC-compliant but rejected by Python
    # since 3.9.5 for security reasons). We strip leading zeros per octet
    # before delegating so that lenient input is still accepted.
    if "." in ip and any(
        part and part[0] == "0" and len(part) > 1
        for part in ip.split(".")
    ):
        ip = ".".join(
            str(int(part)) if part else "0" for part in ip.split(".")
        )
    return str(ipaddress.ip_address(ip))


def _forward_lookup(hostname: str, family: int) -> List[str]:
    """Return forward-resolved addresses for *hostname* within *family*.

    We catch ``socket.gaierror`` and return an empty list rather than raising,
    because a failed forward lookup is a legitimate (negative) confirmation
    result, not an exceptional condition.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    except socket.herror:
        return []
    return list({info[4][0] for info in infos})


class ReverseDNSResolver:
    """Resolve PTR records and confirm them via forward DNS.

    Parameters
    ----------
    timeout:
        Per-call socket timeout in seconds. Passed to ``socket.setdefaulttimeout``
        around each lookup so a hung resolver does not block forever.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = float(timeout)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def resolve(self, ip: str) -> PTRResult:
        """Perform a reverse lookup of *ip*.

        Returns a :class:`PTRResult`. Never raises for normal DNS failures
        (no PTR, forward lookup mismatch, NXDOMAIN); those are encoded in the
        result. Raises :class:`ValueError` for a malformed address and
        :class:`DNSError` for truly unexpected socket errors.
        """
        canonical_ip = _normalise_ip(ip)
        is_v6 = ":" in canonical_ip
        family = socket.AF_INET6 if is_v6 else socket.AF_INET

        try:
            ptr = self._lookup_ptr(canonical_ip, family)
        except OSError as exc:
            raise DNSError(str(exc)) from exc

        if ptr is None:
            return PTRResult(ip=canonical_ip, ptr=None, confirmed=False)

        confirmed = self._confirm(ptr, canonical_ip, family)
        return PTRResult(ip=canonical_ip, ptr=ptr, confirmed=confirmed)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _lookup_ptr(self, canonical_ip: str, family: int) -> Optional[str]:
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self._timeout)
            # ``gethostbyaddr`` performs the PTR query; family is implicit
            # in the address form, so we pass the canonical string directly.
            try:
                name, _aliases, _addrs = socket.gethostbyaddr(canonical_ip)
                return name
            except socket.gaierror:
                return None
            except socket.herror:
                return None
        finally:
            socket.setdefaulttimeout(prev_timeout)

    def _confirm(self, ptr: str, canonical_ip: str, family: int) -> bool:
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self._timeout)
            forward_addrs = _forward_lookup(ptr, family)
        finally:
            socket.setdefaulttimeout(prev_timeout)

        # Compare in canonical form so that, e.g., "::1" and "0:0:0:0:0:0:0:1"
        # are treated as equal.
        normalised: List[str] = []
        for addr in forward_addrs:
            try:
                normalised.append(str(ipaddress.ip_address(addr)))
            except ValueError:
                continue
        return canonical_ip in normalised
