# reverse-dns-py

Reverse DNS resolver that performs a PTR lookup and then a forward-confirmation
lookup so spoofed PTR records are detected.

## Usage

```python
from reverse_dns_py import ReverseDNSResolver, PTRResult

resolver = ReverseDNSResolver(timeout=5.0)
result: PTRResult = resolver.resolve("8.8.8.8")

print(result.ip)         # "8.8.8.8" (canonical form)
print(result.ptr)       # "dns.google" or None
print(result.confirmed) # True if forward lookup of `ptr` contains `ip`
```

## Why this exists

A PTR record alone cannot be trusted: the owner of an IP range can put any
hostname they like in their reverse DNS. To trust the name you have to confirm
it by doing a forward lookup on that name and checking the original IP is
among the returned addresses. That is all this library does.

The deliberate trade-off: we use the system resolver via `socket` rather than
talking DNS directly. That means we cannot set custom RD flags, inspect the
TTL, or read CNAME chains — but it also means there are zero dependencies and
the tests run anywhere `socket.gethostbyaddr` exists.

## Edge cases

- IPv6 addresses are normalised to compressed form before comparison, so a PTR
  returning `0:0:0:0:0:0:0:1` will confirm against an input of `::1`.
- If the forward lookup fails entirely (NXDOMAIN, timeout, network error), the
  result is `ptr=<hostname>, confirmed=False` rather than an exception.
- If there is no PTR at all, the result is `ptr=None, confirmed=False`.
- Malformed input raises `ValueError`; truly unexpected `OSError`s propagate
  as exceptions rather than being swallowed.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

