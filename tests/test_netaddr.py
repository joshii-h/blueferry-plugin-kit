"""Address and interface choice (from blueferry-plugin-shortcuts and -localsend)."""
from __future__ import annotations

import pytest

from blueferry_plugin_kit import netaddr
from blueferry_plugin_kit.netaddr import (
    IFF_POINTOPOINT,
    IFF_UP,
    Interface,
    lan_interfaces,
    parse_interface_list,
)

ROUTES = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""



def test_default_route_picks_lowest_metric() -> None:
    assert netaddr.default_route_interface(ROUTES) == "enp5s0"
    assert netaddr.default_route_interface(ROUTES.splitlines()[0]) is None


VPN_ROUTES = ROUTES + "wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n"


def test_a_vpn_default_route_is_passed_over_for_the_lan(tmp_path) -> None:
    assert netaddr.default_route_interface(VPN_ROUTES) == "enp5s0"
    assert netaddr.default_route_tunnel(VPN_ROUTES) == ("wg0", True)
    assert netaddr.default_route_tunnel(ROUTES) is None
    only = ROUTES.splitlines()[0] + "\n" + VPN_ROUTES.splitlines()[-1]
    assert netaddr.default_route_interface(only) == "wg0"
    assert netaddr.default_route_tunnel(only) == ("wg0", False)
    # A custom name (NetworkManager WireGuard profile) is known by its type.
    for name, kind in (("Immeditech", "65534"), ("enp5s0", "1"), ("vpn1", "512")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "type").write_text(kind + "\n")
    assert netaddr.is_tunnel("Immeditech", tmp_path) and netaddr.is_tunnel("vpn1", tmp_path)
    assert not netaddr.is_tunnel("enp5s0", tmp_path)
    assert netaddr.is_tunnel("tun0", tmp_path) and netaddr.is_tunnel("ppp0", tmp_path)


@pytest.mark.parametrize("setting,allow_all,ok", [
    ("", False, True), ("192.168.1.20", False, True), ("enp5s0", False, True),
    ("0.0.0.0", False, False), ("::", False, False), ("0.0.0.0", True, True),
    ("224.0.0.1", False, False), ("bad name!", False, False),
])
def test_listen_setting_validation(setting, allow_all, ok) -> None:
    assert (netaddr.check_setting(setting, allow_all) is None) is ok


def test_resolve() -> None:
    addresses = {"enp5s0": "192.168.1.20"}
    resolve = lambda s, a=False: netaddr.resolve(  # noqa: E731
        s, a, default_interface=lambda: "enp5s0", address_of=addresses.get,
    )
    assert resolve("") == "192.168.1.20"
    assert resolve("enp5s0") == "192.168.1.20"
    assert resolve("10.0.0.5") == "10.0.0.5"
    with pytest.raises(netaddr.AddressError):
        resolve("wlan9")
    with pytest.raises(netaddr.AddressError):
        resolve("0.0.0.0")
    assert resolve("0.0.0.0", True) == "0.0.0.0"
    with pytest.raises(netaddr.AddressError, match="no default route"):
        netaddr.resolve("", False, default_interface=lambda: None)


def test_only_lan_interfaces_are_used() -> None:
    p2p = IFF_UP | IFF_POINTOPOINT
    system = [
        Interface("lo", "127.0.0.1", "255.0.0.0", IFF_UP | 0x8),
        Interface("wlp7s0", "192.168.1.95", "255.255.255.0"),
        Interface("enp0s20f0u9u2", "192.168.1.4", "255.255.255.0"),
        Interface("enp6s0", "192.168.2.4", "255.255.255.0", 0),            # down
        Interface("docker0", "172.17.0.1", "255.255.0.0", virtual=True),
        Interface("br-26254538c1fe", "172.19.0.1", "255.255.0.0", virtual=True),
        Interface("veth257267f", "169.254.3.3", "255.255.0.0", virtual=True),
        Interface("Immeditech", "10.10.22.16", "255.255.255.255", p2p, virtual=True),
        Interface("wg0", "10.8.0.2", "255.255.255.0", p2p, virtual=True),
        Interface("tun0", "10.9.0.2", "255.255.255.0", p2p, virtual=True),
    ]
    names = [i.name for i in lan_interfaces(source=lambda: system)]
    assert names == ["wlp7s0", "enp0s20f0u9u2"]
    # A configured list wins, but the deny-list still holds.
    chosen = lan_interfaces(["enp0s20f0u9u2", "docker0"], source=lambda: system)
    assert [i.name for i in chosen] == ["enp0s20f0u9u2"]


def test_interface_helpers() -> None:
    assert parse_interface_list(" wlp7s0; enp5s0 ,,") == ["wlp7s0", "enp5s0"]
    lan = Interface("wlp7s0", "192.168.1.95", "255.255.255.0")
    assert lan.contains("192.168.1.4") and not lan.contains("10.0.0.1")
    assert not lan.contains("not-an-address")
    assert netaddr.denied("docker0") and netaddr.denied("wg0") and not netaddr.denied("enp5s0")
    assert netaddr.is_wildcard("0.0.0.0") and not netaddr.is_wildcard("enp5s0")
