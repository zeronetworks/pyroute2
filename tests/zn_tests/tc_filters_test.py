import itertools
import logging
import os
import socket
import subprocess
import pytest

import pyroute2
from pyroute2 import IPRoute, protocols

from tc_nla_constants import TcaNla

log = logging.getLogger(__name__)


EXPECTED_PYROUTE2_VERSION = "0.5.18.3"
IFNAME = "zn-tc-test0"
GNV_IFNAME = "zn-tc-gnv0"

CLSACT_INGRESS = 0xFFFFFFF2
CLSACT_EGRESS = 0xFFFFFFF3

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="Requires root (run: sudo -E pytest -q)",
)

EOPNOTSUPP_CODE = 95


def _run(cmd, check=True):
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, stderr)

    return stdout, stderr, proc.returncode


def _try_run(cmd):
    return _run(cmd, check=False)


def _log_cmd_result(title, stdout, stderr, rc):
    log.debug("%s  rc=%s  out=%s  err=%s",
              title, rc,
              (stdout or "").rstrip(),
              (stderr or "").strip())


def tc_show_state(tag):
    log.debug("==== TC STATE %s (dev %s) ====", tag, IFNAME)
    _log_cmd_result("-- qdisc --", *_try_run(["tc", "qdisc", "show", "dev", IFNAME]))
    _log_cmd_result("-- filters ingress --", *_try_run(["tc", "filter", "show", "dev", IFNAME, "ingress"]))
    _log_cmd_result("-- filters egress --", *_try_run(["tc", "filter", "show", "dev", IFNAME, "egress"]))
    log.debug("================================")


def _get_filter_prio(flt):
    return (flt['info'] >> 16) & 0xFFFF


def _find_filter(ipr, ifindex, parent, prio, chain=None):
    filters = ipr.get_filters(index=ifindex, parent=parent)
    for flt in filters:
        if flt.get_attr(TcaNla.OPTIONS) is None:
            continue
        if _get_filter_prio(flt) != prio:
            continue
        if chain is not None:
            flt_chain = flt.get_attr(TcaNla.CHAIN)
            if flt_chain != chain:
                continue
        return flt
    return None


def _assert_flower_attrs(flt, expected_kind, expected_nla_attrs):
    kind = flt.get_attr(TcaNla.KIND)
    assert kind == expected_kind, "expected kind %s, got %s" % (expected_kind, kind)

    options = flt.get_attr(TcaNla.OPTIONS)
    assert options is not None, "TCA_OPTIONS missing from filter"

    for nla_name, expected_val in expected_nla_attrs.items():
        actual = options.get_attr(nla_name)
        if expected_val is None:
            assert actual is not None, "%s should exist but is missing" % nla_name
        else:
            assert actual == expected_val, (
                "%s: expected %r, got %r" % (nla_name, expected_val, actual)
            )


def _assert_action_kind(flt, expected_kind, action_nla_name, action_index=1):
    options = flt.get_attr(TcaNla.OPTIONS)
    assert options is not None, "TCA_OPTIONS missing"
    acts = options.get_attr(action_nla_name)
    assert acts is not None, "%s missing" % action_nla_name
    act_prio = acts.get_attr('TCA_ACT_PRIO_%d' % action_index)
    assert act_prio is not None, "TCA_ACT_PRIO_%d missing" % action_index
    act_kind = act_prio.get_attr(TcaNla.ACT_KIND)
    assert act_kind == expected_kind, (
        "action kind: expected %s, got %s" % (expected_kind, act_kind)
    )


def get_interface_index(ipr, interface_name):
    for link in ipr.get_links():
        if link.get_attr("IFLA_IFNAME") == interface_name:
            return link["index"]
    return None


def ensure_clsact(ipr, ifindex):
    try:
        ipr.tc("add", "clsact", ifindex)
    except Exception as e:
        if "File exists" not in str(e):
            raise


def delete_clsact(ipr, ifindex):
    try:
        ipr.tc("del", "clsact", ifindex)
    except Exception as e:
        code = getattr(e, 'code', None)
        if "No such file or directory" not in str(e) and code != EOPNOTSUPP_CODE:
            raise


@pytest.fixture(scope="session", autouse=True)
def require_pyroute2_version_once():
    if pyroute2.__version__ != EXPECTED_PYROUTE2_VERSION:
        pytest.skip("expected pyroute2 {}, got {}".format(
            EXPECTED_PYROUTE2_VERSION, pyroute2.__version__))


@pytest.fixture(scope="session")
def ipr():
    ipr_obj = IPRoute()
    try:
        yield ipr_obj
    finally:
        ipr_obj.close()


@pytest.fixture(scope="session", autouse=True)
def dummy_interface():
    _try_run(["ip", "link", "del", IFNAME])
    _run(["ip", "link", "add", IFNAME, "type", "dummy"])
    _run(["ip", "link", "set", IFNAME, "up"])

    try:
        yield
    finally:
        _try_run(["ip", "link", "del", IFNAME])


@pytest.fixture(scope="session", autouse=True)
def gnv_interface():
    """
    Create a dedicated dummy interface that represents gnv0 for the whole test run.
    """
    _try_run(["ip", "link", "del", GNV_IFNAME])

    _run(["ip", "link", "add", GNV_IFNAME, "type", "dummy"])
    _run(["ip", "link", "set", GNV_IFNAME, "up"])

    try:
        yield
    finally:
        _try_run(["ip", "link", "del", GNV_IFNAME])


@pytest.fixture(scope="session")
def gnv_ifindex(ipr, gnv_interface):
    idx = get_interface_index(ipr, GNV_IFNAME)

    if idx is None:
        pytest.skip("Geneve dummy interface not found: {}".format(GNV_IFNAME))

    return idx


@pytest.fixture(scope="session")
def ifindex(ipr, dummy_interface):
    idx = get_interface_index(ipr, IFNAME)

    if idx is None:
        pytest.skip("Dummy interface not found: {}".format(IFNAME))

    return idx


@pytest.fixture(scope="session", autouse=True)
def reset_clsact_before_suite(ipr, ifindex, gnv_ifindex):
    tc_show_state("BEFORE SUITE RESET")

    delete_clsact(ipr, ifindex)
    ensure_clsact(ipr, ifindex)

    delete_clsact(ipr, gnv_ifindex)
    ensure_clsact(ipr, gnv_ifindex)

    tc_show_state("AFTER SUITE RESET")


@pytest.fixture(scope="session")
def _prio_counter():
    """Session-wide counter for generating unique priority values."""
    return itertools.count(100, 100)


@pytest.fixture(scope="function")
def priority(_prio_counter):
    """
    Provide a unique TC filter priority for each test.

    TC filters are identified by (parent, prio, protocol, handle). Using
    unique priorities prevents 'file exists' errors and allows filters
    from different tests to coexist without cleanup between tests.
    """
    return next(_prio_counter)


@pytest.fixture(scope="function", autouse=True)
def tc_state_before_after_test(request):
    """
    Run with `-s` to see output.
    """
    tc_show_state("BEFORE {}".format(request.node.name))

    try:
        yield
    finally:
        tc_show_state("AFTER {}".format(request.node.name))


def test_flower_ip_port(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "flower",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        src_ip='192.168.1.0',
        dst_ip='10.0.0.1',
        ip_proto="tcp",
        dst_port=60,
        action=[
            {
                'kind': 'gact',
                'action': 'drop',
            }
        ])

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    _assert_flower_attrs(flt, 'flower', {
        TcaNla.FLOWER_KEY_IPV4_SRC: '192.168.1.0',
        TcaNla.FLOWER_KEY_IPV4_DST: '10.0.0.1',
        TcaNla.FLOWER_KEY_IP_PROTO: 6,
        TcaNla.FLOWER_KEY_TCP_DST: 60,
    })
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)


def test_flower_ip_cidr_port(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "flower",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        src_ip='192.168.1.0/24',
        dst_ip='10.0.0.1/24',
        ip_proto="udp",
        dst_port=68,
        action=[
            {
                'kind': 'gact',
                'action': 'drop',
            }
        ])

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    _assert_flower_attrs(flt, 'flower', {
        TcaNla.FLOWER_KEY_IPV4_SRC: '192.168.1.0',
        TcaNla.FLOWER_KEY_IPV4_SRC_MASK: '255.255.255.0',
        TcaNla.FLOWER_KEY_IP_PROTO: 17,
        TcaNla.FLOWER_KEY_UDP_DST: 68,
    })
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)

def test_flower_ipv6(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "flower",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        src_ip='fe80::1ff:fe23:4567:890a',
        dst_ip='fe80::1ff:fe23:4567:891b',
        action=[
            {
                'kind': 'gact',
                'action': 'drop',
            }
        ])

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"

    options = flt.get_attr(TcaNla.OPTIONS)
    actual_src = options.get_attr(TcaNla.FLOWER_KEY_IPV6_SRC)
    actual_dst = options.get_attr(TcaNla.FLOWER_KEY_IPV6_DST)
    expected_src = socket.inet_ntop(socket.AF_INET6,
                                    socket.inet_pton(socket.AF_INET6, 'fe80::1ff:fe23:4567:890a'))
    expected_dst = socket.inet_ntop(socket.AF_INET6,
                                    socket.inet_pton(socket.AF_INET6, 'fe80::1ff:fe23:4567:891b'))
    assert actual_src == expected_src, "IPV6_SRC: expected %s, got %s" % (expected_src, actual_src)
    assert actual_dst == expected_dst, "IPV6_DST: expected %s, got %s" % (expected_dst, actual_dst)

    actual_src_mask = options.get_attr(TcaNla.FLOWER_KEY_IPV6_SRC_MASK)
    assert actual_src_mask is not None, "IPV6_SRC_MASK should exist"
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)

def test_flower_enc_fields(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "flower",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        enc_src_ip="192.168.1.0",
        enc_dst_ip="10.0.0.1",
        enc_key_id=124,
        enc_dst_port=6000,
        action=[{"kind": "gact", "action": "drop"}],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    _assert_flower_attrs(flt, 'flower', {
        TcaNla.FLOWER_KEY_ENC_IPV4_SRC: '192.168.1.0',
        TcaNla.FLOWER_KEY_ENC_IPV4_DST: '10.0.0.1',
        TcaNla.FLOWER_KEY_ENC_KEY_ID: 124,
        TcaNla.FLOWER_KEY_ENC_UDP_DST_PORT: 6000,
    })
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)


def test_flower_geneve_opts(ipr, ifindex, priority):
    ipr.tc(
        "add-filter", "flower", ifindex,
        parent=CLSACT_INGRESS,
        protocol=protocols.ETH_P_IP,
        prio=priority,
        enc_src_ip='1.1.1.1',
        enc_key_id=1234,
        enc_dst_port=6000,
        geneve_opts="0141:20:00000200",
        action=[
            {"kind": "gact", "action": "drop"}
        ],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    _assert_flower_attrs(flt, 'flower', {
        TcaNla.FLOWER_KEY_ENC_IPV4_SRC: '1.1.1.1',
        TcaNla.FLOWER_KEY_ENC_KEY_ID: 1234,
        TcaNla.FLOWER_KEY_ENC_OPTS: None,
    })
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)


@pytest.mark.xfail(reason="ip range is not supported in flower filter")
def test_flower_ip_range(ipr, ifindex, priority):
    ipr.tc(
        "add-filter", "flower", ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        src_ip='192.168.1.0-192.168.1.10',
        action=[{"kind": "gact", "action": "drop"}],
    )


def test_flower_port_range(ipr, ifindex, priority):
    ipr.tc(
        "add-filter", "flower", ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        eth_type=protocols.ETH_P_IP,
        ip_proto="tcp",
        dst_port_min=8000,
        dst_port_max=9000,
        src_port_min=1000,
        src_port_max=2000,
        src_ip='10.1.1.1',
        action=[{"kind": "gact", "action": "drop"}],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    _assert_flower_attrs(flt, 'flower', {
        TcaNla.FLOWER_KEY_IP_PROTO: 6,
        TcaNla.FLOWER_KEY_PORT_DST_MIN: 8000,
        TcaNla.FLOWER_KEY_PORT_DST_MAX: 9000,
        TcaNla.FLOWER_KEY_IPV4_SRC: '10.1.1.1',
    })
    _assert_action_kind(flt, 'gact', TcaNla.FLOWER_ACT)


def test_flower_ip_frags(ipr, ifindex, priority):
    ipr.tc(
        "add-filter", "flower", ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        ip_flags="frag",
        action=[{"kind": "gact", "action": "drop"}],
    )

    ipr.tc(
        "add-filter", "flower", ifindex,
        parent=CLSACT_INGRESS,
        prio=priority + 1,
        ip_flags="nofrag",
        action=[{"kind": "gact", "action": "drop"}],
    )

    frag_flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert frag_flt is not None, "frag filter not found"
    _assert_flower_attrs(frag_flt, 'flower', {
        TcaNla.FLOWER_KEY_FLAGS: 1,
        TcaNla.FLOWER_KEY_FLAGS_MASK: 1,
    })
    _assert_action_kind(frag_flt, 'gact', TcaNla.FLOWER_ACT)

    nofrag_flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority + 1)
    assert nofrag_flt is not None, "nofrag filter not found"
    _assert_flower_attrs(nofrag_flt, 'flower', {
        TcaNla.FLOWER_KEY_FLAGS: 0,
        TcaNla.FLOWER_KEY_FLAGS_MASK: 1,
    })
    _assert_action_kind(nofrag_flt, 'gact', TcaNla.FLOWER_ACT)


def test_pedit_munge_set_src(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        action=[
            {
                "kind": "pedit",
                "extended": True,
                "munge": [
                    {"htype": "eth", "cmd": "set", "field": "src", "value": "12:34:56:78:9a:bc"}
                ],
                "tc_action": "pipe",
            }
        ],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    assert flt.get_attr(TcaNla.KIND) == 'matchall'
    _assert_action_kind(flt, 'pedit', TcaNla.MATCHALL_ACT)


def test_pedit_munge_set_dst(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        action=[
            {
                "kind": "pedit",
                "extended": True,
                "munge": [
                    {"htype": "eth", "cmd": "set", "field": "dst", "value": "12:34:56:78:9a:bc"}
                ],
                "tc_action": "pipe",
            }
        ],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    assert flt.get_attr(TcaNla.KIND) == 'matchall'
    _assert_action_kind(flt, 'pedit', TcaNla.MATCHALL_ACT)


def test_tunnel_key(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        action=[
            {
                "kind": "tunnel_key",
                "action": "set",
                "tc_action": "pipe",
                "id": 48813,
                "src_ip": "0.0.0.0",
                "dst_ip": "192.168.4.106",
                "dst_port": 6081,
                "geneve_opts": "0141:20:00000201",
            }
        ],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority)
    assert flt is not None, "filter not found after creation"
    assert flt.get_attr(TcaNla.KIND) == 'matchall'
    _assert_action_kind(flt, 'tunnel_key', TcaNla.MATCHALL_ACT)


def test_chain(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        chain=10,
        action=[{"kind": "gact", "action": "drop"}],
    )

    flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority, chain=10)
    assert flt is not None, "filter not found after creation"
    assert flt.get_attr(TcaNla.KIND) == 'matchall'
    assert flt.get_attr(TcaNla.CHAIN) == 10
    _assert_action_kind(flt, 'gact', TcaNla.MATCHALL_ACT)


def test_goto_chain(ipr, ifindex, priority):
    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        action=[{"kind": "gact", "action": "goto", "chain": 20}],
    )

    ipr.tc(
        "add-filter",
        "matchall",
        ifindex,
        parent=CLSACT_INGRESS,
        prio=priority,
        chain=20,
        action=[{"kind": "gact", "action": "drop"}],
    )

    goto_flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority, chain=0)
    assert goto_flt is not None, "goto filter not found"
    assert goto_flt.get_attr(TcaNla.KIND) == 'matchall'
    _assert_action_kind(goto_flt, 'gact', TcaNla.MATCHALL_ACT)

    chain_flt = _find_filter(ipr, ifindex, CLSACT_INGRESS, priority, chain=20)
    assert chain_flt is not None, "chain-20 drop filter not found"
    assert chain_flt.get_attr(TcaNla.KIND) == 'matchall'
    _assert_action_kind(chain_flt, 'gact', TcaNla.MATCHALL_ACT)
