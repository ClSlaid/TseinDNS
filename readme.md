# Tsein DNS
Tsein DNS is a robust and high performance DNS resolver supporting multiple DNS protocols.

> *Tsein* indicates *Arrow* in Hunanese.

*It is currently still under development.*

## Software Architecture Planning
The software will implements a connection manager, a DNS cache and other utilities for DNS resolving.

### Connection Manager
As is explained in [RFC7766](https://datatracker.ietf.org/doc/html/rfc7766) and [RFC7858](https://datatracker.ietf.org/doc/html/rfc7858), to save the overhead of TLS/TCP handshacking in DNS over TCP and DNS over TLS connections, the TLS/TCP connections between server and clients should be kept as long as possible. 

Meanwhile, a single process can only open limited bunch of files, which is also how `socket`s access as, in Linux system. When the time comes, some connections have to be droped.

If implemented properly, along with every DNS packet should comes a `pipe`, upper layers of the server's transaction routine could be simplified.

### DNS cache

It's obvious that even in the world of domain names we can still come up with [locality of references](https://en.wikipedia.org/wiki/Locality_of_reference). So that a simple LRU cache can empower us with ideal hit rate and memory usage.

## License

This work is licensed under Mozilla Public License v2.0, Use it for free.