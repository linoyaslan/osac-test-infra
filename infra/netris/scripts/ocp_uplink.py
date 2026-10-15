#!/usr/bin/env python3
"""Resolve the SNO's fabric port and reconcile its Netris VNet.

The two commands intentionally share only read-only discovery and API helpers.
``resolve`` never changes the lab; ``reconcile`` only changes the OCP VNet's
port list after Ansible has created the VNet if necessary.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


class UplinkError(Exception):
    """A discovery or reconciliation failure safe to show in Ansible output."""


MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
IFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_.:-]+$")
ALIAS_PATTERN = re.compile(r"^alias\s+(\S+)=(['\"])(.*)\2$")


def mac_address(value: str) -> str:
    value = value.strip().lower()
    if not MAC_PATTERN.fullmatch(value):
        raise UplinkError(f"Invalid network adapter MAC address: {value!r}")
    return value


def run(argv: list[str], *, timeout: int = 30) -> str:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UplinkError(f"Could not run {argv[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise UplinkError(f"{argv[0]} failed: {detail or 'no output'}")
    return result.stdout


def ssh(host: str, user: str, key: str, command: str) -> str:
    return run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-i", key,
            f"{user}@{host}",
            command,
        ],
        timeout=12,
    )


def aliases(path: Path) -> dict[str, str]:
    """Read Cloudsim's generated SSH aliases as data, never by sourcing them."""
    if not path.is_file():
        return {}
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = ALIAS_PATTERN.fullmatch(line.strip())
        if not match:
            continue
        try:
            destination = shlex.split(match.group(3))[-1]
            address = destination.rsplit("@", 1)[1]
            found[match.group(1)] = str(ipaddress.ip_address(address))
        except (IndexError, ValueError):
            continue
    return found


def api_request(base_url: str, path: str, *, method: str = "GET", body: dict | None = None) -> object:
    cookie = os.environ.get("NETRIS_SESSION_COOKIE", "")
    if not cookie:
        raise UplinkError("Netris session cookie is unavailable")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Cookie": f"connect.sid={cookie}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, headers=headers, method=method)
    context = ssl._create_unverified_context() if os.environ.get("NETRIS_VALIDATE_CERTS") == "false" else None
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            payload = response.read()
            result = json.loads(payload) if payload else {}
    except (OSError, ValueError) as exc:
        raise UplinkError(f"Netris {method} {path} failed: {exc}") from exc
    if not isinstance(result, dict):
        raise UplinkError(f"Netris {method} {path} returned an unexpected response")
    if result.get("isSuccess") is False:
        raise UplinkError(f"Netris {method} {path} was rejected: {result.get('message', 'unknown error')}")
    if method == "GET" and "data" not in result:
        raise UplinkError(f"Netris {method} {path} returned no data field")
    return result.get("data")


def api_list(base_url: str, path: str) -> list[dict]:
    data = api_request(base_url, path)
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise UplinkError(f"Netris {path} did not return a list")
    return data


def vm_names(pattern: str) -> tuple[list[str], str]:
    try:
        name_pattern = re.compile(pattern)
    except re.error as exc:
        raise UplinkError(f"Invalid ocp_vm_name_pattern: {exc}") from exc
    names = [name for name in run(["virsh", "list", "--all", "--name"]).splitlines() if name]
    matches = [name for name in names if name_pattern.search(name)]
    if len(matches) != 1:
        raise UplinkError(f"Expected one SNO VM matching {pattern!r}; found {matches}")
    return names, matches[0]


def guest_mac(host: str, interface: str, host_key: str, snapshot_key: str) -> str:
    if not IFACE_PATTERN.fullmatch(interface):
        raise UplinkError(f"Invalid guest interface name: {interface!r}")
    candidates = [("root", host_key), ("core", host_key), ("core", snapshot_key)]
    candidates = [(user, key) for user, key in candidates if Path(key).is_file()]
    if not candidates:
        raise UplinkError("No SSH key is available for the SNO management interface")
    errors = []
    for attempt in range(12):
        for user, key in candidates:
            try:
                return mac_address(ssh(host, user, key, f"cat /sys/class/net/{interface}/address"))
            except UplinkError as exc:
                errors.append(str(exc))
        if attempt < 11:
            time.sleep(5)
    raise UplinkError(
        f"Could not read {interface} from SNO management address {host} using root/core SSH; "
        f"last error: {errors[-1]}"
    )


def udp_interfaces(vm: str) -> list[dict]:
    try:
        root = ET.fromstring(run(["virsh", "dumpxml", "--inactive", vm]))
    except ET.ParseError as exc:
        raise UplinkError(f"Invalid libvirt XML for {vm}: {exc}") from exc
    interfaces = []
    for interface in root.findall("./devices/interface[@type='udp']"):
        mac = interface.find("mac")
        source = interface.find("source")
        local = source.find("local") if source is not None else None
        if mac is None or source is None or local is None:
            raise UplinkError(f"UDP adapter in {vm} lacks MAC or tunnel endpoint")
        remote_endpoint = (source.get("address"), source.get("port"))
        local_endpoint = (local.get("address"), local.get("port"))
        if not all(remote_endpoint + local_endpoint):
            raise UplinkError(f"UDP adapter in {vm} has an incomplete tunnel endpoint")
        interfaces.append(
            {
                "vm": vm,
                "mac": mac_address(mac.get("address", "")),
                "local": local_endpoint,
                "remote": remote_endpoint,
            }
        )
    return interfaces


def switch_interfaces(host: str, key: str, expected_mac: str) -> list[str]:
    command = (
        'for nic in /sys/class/net/*; do '
        'if [ -f "$nic/address" ]; then '
        'printf "%s %s\\n" "${nic##*/}" "$(cat "$nic/address")"; '
        'fi; done'
    )
    output = ssh(host, "cumulus", key, command)
    matches = sorted(
        {
            fields[0]
            for line in output.splitlines()
            if len(fields := line.split()) == 2
            and fields[1].lower() == expected_mac
            and IFACE_PATTERN.fullmatch(fields[0])
        }
    )
    if not matches:
        raise UplinkError(f"Could not find a leaf adapter with MAC {expected_mac} on {host}")
    return matches


def resolve(args: argparse.Namespace) -> dict:
    names, vm = vm_names(args.vm_name_pattern)
    known_ips = aliases(Path(args.aliases_path))
    management_ip = args.vm_mgmt_ip or known_ips.get(vm)
    if not management_ip:
        raise UplinkError(f"Management IP for {vm} is missing; set ocp_vm_mgmt_ip or restore Cloudsim aliases")
    try:
        management_ip = str(ipaddress.ip_address(management_ip))
    except ValueError as exc:
        raise UplinkError(f"Invalid management IP for {vm}: {management_ip!r}") from exc

    selected_mac = guest_mac(management_ip, args.guest_interface, args.host_key, args.snapshot_key)
    selected = [interface for interface in udp_interfaces(vm) if interface["mac"] == selected_mac]
    if len(selected) != 1:
        raise UplinkError(
            f"Guest {args.guest_interface} MAC {selected_mac} does not uniquely match a UDP adapter in {vm}"
        )
    selected = selected[0]

    peers = [
        interface
        for name in names if name != vm
        for interface in udp_interfaces(name)
        if interface["local"] == selected["remote"] and interface["remote"] == selected["local"]
    ]
    if len(peers) != 1:
        raise UplinkError(f"Expected one reverse UDP tunnel peer for {vm} {selected_mac}; found {len(peers)}")
    peer = peers[0]

    devices = api_list(args.controller_url, "/api/v2/hw")
    leaf_devices = [item for item in devices if item.get("name") == peer["vm"]]
    if len(leaf_devices) != 1:
        raise UplinkError(f"Netris inventory does not uniquely identify leaf VM {peer['vm']}")
    leaf_ip = leaf_devices[0].get("mgmtAddress", "").split("/", 1)[0] or known_ips.get(peer["vm"])
    if not leaf_ip:
        raise UplinkError(f"Management IP for leaf VM {peer['vm']} is missing")
    try:
        leaf_ip = str(ipaddress.ip_address(leaf_ip))
    except ValueError as exc:
        raise UplinkError(f"Invalid management IP for leaf VM {peer['vm']}: {leaf_ip!r}") from exc
    leaf_interfaces = switch_interfaces(leaf_ip, args.host_key, peer["mac"])
    links = api_list(args.controller_url, "/api/v2/link")
    leaf_endpoints = {f"{interface}@{peer['vm']}" for interface in leaf_interfaces}
    uplinks = []
    for link in links:
        local = link.get("local")
        remote = link.get("remote")
        if not isinstance(local, dict) or not isinstance(remote, dict):
            continue
        endpoints = [local.get("name"), remote.get("name")]
        for leaf_endpoint in leaf_endpoints.intersection(endpoints):
            other = endpoints[1] if endpoints[0] == leaf_endpoint else endpoints[0]
            if (
                isinstance(other, str)
                and other.endswith(f"@{vm}")
                and re.fullmatch(r"eth\d+", other.split("@", 1)[0])
            ):
                uplinks.append((leaf_endpoint, other))
    if len(uplinks) != 1:
        raise UplinkError(
            f"Netris links do not uniquely map leaf interfaces with MAC {peer['mac']} "
            f"({leaf_interfaces}) to an ethN port on {vm}: {uplinks}"
        )
    leaf_endpoint, server_port = uplinks[0]
    return {
        "vm_name": vm,
        "management_ip": management_ip,
        "guest_interface": args.guest_interface,
        "guest_mac": selected_mac,
        "leaf_port": leaf_endpoint,
        "server_port": server_port,
    }


def full_port_name(port: dict) -> str:
    name = port.get("name")
    switch = port.get("switch")
    switch_name = port.get("switchName") or (switch.get("name") if isinstance(switch, dict) else None)
    short_name = port.get("port")
    if isinstance(short_name, str) and isinstance(switch_name, str):
        short_name = re.sub(r"\([^)]*\)$", "", short_name)
        if short_name and switch_name:
            return f"{short_name}@{switch_name}"

    if isinstance(name, str):
        match = re.fullmatch(r"([^()\s@]+)(?:\([^)]*\))?@([^\s()]+)(?:\s+\([^)]*\))?", name.strip())
        if match:
            return f"{match.group(1)}@{match.group(2)}"
    raise UplinkError(f"Unrecognized Netris VNet port record: {port}")


def vnet_detail(base_url: str, vnet_id: int) -> dict:
    detail = api_request(base_url, f"/api/v2/vnet/{vnet_id}")
    if not isinstance(detail, dict):
        raise UplinkError(f"Netris VNet {vnet_id} detail was not an object")
    return detail


def check_vnet_identity(detail: dict, name: str, vpc_id: int) -> None:
    if detail.get("name") != name or int((detail.get("vpc") or {}).get("id", -1)) != vpc_id:
        raise UplinkError(f"VNet {name} has an unexpected name or VPC; refusing to change it")


def reconcile(args: argparse.Namespace) -> dict:
    vnets = api_list(args.controller_url, "/api/v2/vnet")
    matches = [item for item in vnets if item.get("name") == args.vnet_name]
    if len(matches) != 1:
        raise UplinkError(f"Expected one existing VNet named {args.vnet_name}; found {len(matches)}")
    vnet_id = int(matches[0]["id"])
    detail = vnet_detail(args.controller_url, vnet_id)
    check_vnet_identity(detail, args.vnet_name, args.vpc_id)

    for other in vnets:
        if int(other.get("id", -1)) == vnet_id:
            continue
        if any(full_port_name(port) == args.server_port for port in other.get("ports") or []):
            raise UplinkError(f"Port {args.server_port} is already attached to VNet {other.get('name')}")

    ports = detail.get("ports") or []
    if len(ports) > 1:
        raise UplinkError(f"VNet {args.vnet_name} has {len(ports)} ports; refusing to remove unrelated attachments")
    if ports:
        current = full_port_name(ports[0])
        if current != args.server_port and current.split("@", 1)[-1] != args.server_port.split("@", 1)[-1]:
            raise UplinkError(f"VNet {args.vnet_name} contains unrelated port {current}; refusing to replace it")
    changed = not ports or full_port_name(ports[0]) != args.server_port or ports[0].get("accessMode") is not True
    if changed:
        api_request(
            args.controller_url,
            f"/api/v2/vnet/{vnet_id}",
            method="PUT",
            body={"ports": [{"name": args.server_port, "accessMode": True}]},
        )

    actual = vnet_detail(args.controller_url, vnet_id)
    check_vnet_identity(actual, args.vnet_name, args.vpc_id)
    actual_ports = actual.get("ports") or []
    if (
        len(actual_ports) != 1
        or full_port_name(actual_ports[0]) != args.server_port
        or actual_ports[0].get("accessMode") is not True
    ):
        raise UplinkError(f"VNet {args.vnet_name} did not retain port {args.server_port} in access mode")
    return {"changed": changed, "vnet_id": vnet_id, "server_port": args.server_port}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    resolver = subparsers.add_parser("resolve")
    resolver.add_argument("--controller-url", required=True)
    resolver.add_argument("--vm-name-pattern", required=True)
    resolver.add_argument("--guest-interface", required=True)
    resolver.add_argument("--host-key", required=True)
    resolver.add_argument("--snapshot-key", required=True)
    resolver.add_argument("--aliases-path", default="/root/.cloudsim_aliases")
    resolver.add_argument("--vm-mgmt-ip", default="")
    reconciler = subparsers.add_parser("reconcile")
    reconciler.add_argument("--controller-url", required=True)
    reconciler.add_argument("--vnet-name", required=True)
    reconciler.add_argument("--vpc-id", required=True, type=int)
    reconciler.add_argument("--server-port", required=True)
    args = parser.parse_args()
    try:
        result = resolve(args) if args.operation == "resolve" else reconcile(args)
    except (UplinkError, KeyError, TypeError, ValueError) as exc:
        print(f"OCP uplink {args.operation} failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
