"""Reject path traversal before any request can reach Proxmoxer.

Proxmoxer splits string resource IDs at '/' and normalizes '..' components.
These tests exercise the real registered MCP tools, not just the validator.
"""

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from tests.conftest import RecordingProxmox, build_server, call_tool, make_context


@pytest.mark.parametrize(
    "tool,argument,base",
    [
        ("get_node_status", "node", {"node": "pve"}),
        ("list_vms", "node", {"node": "pve"}),
        ("get_vm_config", "node", {"node": "pve", "vmid": 101}),
        ("get_container_config", "node", {"node": "pve", "vmid": 101}),
        ("get_storage_content", "storage", {"node": "pve", "storage": "local"}),
        ("get_task_status", "upid", {"node": "pve", "upid": "UPID:pve:123"}),
        ("delete_vm_snapshot", "snapname", {"node": "pve", "vmid": 101, "snapname": "snap1"}),
        (
            "rollback_container_snapshot",
            "snapname",
            {"node": "pve", "vmid": 101, "snapname": "snap1"},
        ),
    ],
)
@pytest.mark.parametrize(
    "invalid",
    [
        ".", "..", "../status", "snapshot/../../", "/foo", "foo\\\\bar",
        "%2f", "%2e%2e", "foo?x", "foo#x", "", "foo bar",
    ],
)
def test_dynamic_api_path_rejects_unsafe_segments(
    proxmox: RecordingProxmox,
    tool: str,
    argument: str,
    base: dict[str, object],
    invalid: str,
) -> None:
    mcp = build_server("all")
    args = {**base, argument: invalid}
    with pytest.raises(ToolError, match=f"{argument} must be a single safe"):
        call_tool(mcp, tool, args, make_context(proxmox, settings_level="all"))
    assert proxmox.calls == [], "invalid inputs must fail before any API request"


@pytest.mark.parametrize(
    "tool,args,path",
    [
        ("get_node_status", {"node": "pve-01"}, "nodes/pve-01/status"),
        (
            "get_task_status",
            {"node": "pve-01", "upid": "UPID:pve-01:00001:0AA:task:101:root@pam:"},
            "nodes/pve-01/tasks/UPID:pve-01:00001:0AA:task:101:root@pam:/status",
        ),
        (
            "get_storage_content",
            {"node": "pve-01", "storage": "local-lvm"},
            "nodes/pve-01/storage/local-lvm/content",
        ),
        (
            "delete_vm_snapshot",
            {"node": "pve-01", "vmid": 101, "snapname": "before_upgrade.1"},
            "nodes/pve-01/qemu/101/snapshot/before_upgrade.1",
        ),
    ],
)
def test_normal_proxmox_identifiers_continue_to_work(
    proxmox: RecordingProxmox, tool: str, args: dict[str, object], path: str
) -> None:
    mcp = build_server("all")
    call_tool(mcp, tool, args, make_context(proxmox, settings_level="all"))
    assert proxmox.last["path"] == path
