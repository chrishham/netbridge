"""Network facts the journey needs."""
import ipaddress
import socket


def private_ipv4() -> str:
    """IPv4 of the default-route interface.

    Targets must not listen on loopback: the agent always blocks loopback
    destinations with its default config, which is what we want to test.
    connect() on a UDP socket only selects the route; no packet is sent.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1
        ip = s.getsockname()[0]
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        raise RuntimeError(f"no usable non-loopback IPv4 (default route source is {ip})")
    return ip


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """True if something already accepts connections on host:port."""
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


if __name__ == "__main__":
    # CI maps --target-hostname to this address in the hosts file
    print(private_ipv4())
