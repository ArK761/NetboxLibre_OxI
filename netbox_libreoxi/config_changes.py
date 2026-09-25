"""Vendor-neutral semantic comparison of device configurations.

Configurations are parsed into a tree of sections (indentation based for
Cisco/Arista/Huawei/HP/Aruba/Fortinet style, brace based for Juniper/VyOS
style, "/path" headers for MikroTik) and the two trees are compared section by
section. Order-only changes are ignored. Removed and added lines that set the
same attribute in the same section are reported as a single modification, and
every change is described in human readable form, for example:

    Interface GigabitEthernet1/0/5: access VLAN changed 10 -> 20
    VLAN 30: name changed "Guests" -> "Visitors"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


IGNORED_LINES = {"!", "#", "end", "next", "exit", "quit", "return", "exit all", "}"}
IGNORED_PREFIXES = (
    "!",
    "#",
    "/*",
    "Building configuration",
    "Current configuration",
    "ntp clock-period",
)

# Line prefixes whose value may contain several words. The key of such a line
# is the prefix itself, so "description A" and "description B" pair up.
KEY_PREFIXES = (
    ("snmp-server", "location"),
    ("snmp-server", "contact"),
    ("snmp-agent", "sys-info", "location"),
    ("snmp-agent", "sys-info", "contact"),
    ("switchport", "access", "vlan"),
    ("switchport", "trunk", "native", "vlan"),
    ("switchport", "trunk", "allowed", "vlan"),
    ("switchport", "mode"),
    ("port", "default", "vlan"),
    ("port", "trunk", "pvid", "vlan"),
    ("port", "trunk", "allow-pass", "vlan"),
    ("port", "link-type"),
    ("ip", "address"),
    ("ipv6", "address"),
    ("ip", "default-gateway"),
    ("vlan", "access"),
    ("vlan", "trunk", "native"),
    ("vlan", "trunk", "allowed"),
    ("native-vlan-id",),
    ("members",),
    ("untagged",),
    ("tagged",),
)
VALUE_KEYWORDS = {"description", "name", "alias", "hostname", "sysname", "comment", "comments", "location", "contact"}
NEGATIONS = ("no ", "undo ", "not ")

# (regex over the key, label) used to name the attribute in change messages.
ATTRIBUTE_LABELS = (
    (r"(^| )(description|comments?)$", "description"),
    (r"(^| )alias$", "alias"),
    (r"(^| )members$", "VLAN members"),
    (r"(^| )name$", "name"),
    (r"^(hostname|sysname|host-name)$", "hostname"),
    (r"(switchport access vlan|port default vlan|vlan access)$", "access VLAN"),
    (r"(trunk allowed vlan|allow-pass vlan|vlan trunk allowed|vlan members)", "allowed VLANs"),
    (r"(native vlan|native-vlan-id|pvid vlan|vlan trunk native)", "native VLAN"),
    (r"(switchport mode|port link-type|port-mode|interface-mode)", "port mode"),
    (r"^untagged$", "untagged ports"),
    (r"^tagged$", "tagged ports"),
    (r"(ipv6 address)$", "IPv6 address"),
    (r"(ip address|^address)", "IP address"),
    (r"vlan-?id$", "VLAN ID"),
    (r"^(set )?speed$", "speed"),
    (r"^(set )?duplex$", "duplex"),
    (r"^(set )?mtu$", "MTU"),
    (r"(^| )location$", "location"),
    (r"(^| )contact$", "contact"),
)
ADMIN_STATE = {"shutdown", "disable", "set status down", "shutdown true"}


@dataclass
class Node:
    text: str
    children: list = field(default_factory=list)


@dataclass
class Change:
    action: str  # added | removed | modified
    category: str  # Interface | VLAN | System | Section ...
    obj: str
    message: str
    old: str = ""
    new: str = ""


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _clean_lines(content: str) -> list[tuple[int, str]]:
    lines = []
    pending = ""
    for raw in content.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if line.endswith("\\"):  # MikroTik line continuation
            pending += line[:-1].rstrip() + " "
            continue
        if pending:
            line = pending + line.strip()
            pending = ""
        stripped = line.strip()
        if not stripped or stripped in IGNORED_LINES or stripped.startswith(IGNORED_PREFIXES):
            continue
        lines.append((len(line) - len(line.lstrip()), line.strip()))
    return lines


def _is_brace_style(content: str) -> bool:
    opening = sum(1 for line in content.splitlines() if line.rstrip().endswith("{"))
    return opening > 0 and opening >= content.count("}") * 0.5


def _parse_braces(content: str) -> Node:
    root = Node("")
    stack = [root]
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "/*", "##")):
            continue
        if line.startswith("}"):
            if len(stack) > 1:
                stack.pop()
            continue
        if line.endswith("{"):
            node = Node(line[:-1].strip())
            stack[-1].children.append(node)
            stack.append(node)
        else:
            stack[-1].children.append(Node(line.rstrip(";").strip()))
    return root


def _parse_indent(content: str) -> Node:
    root = Node("")
    stack = [(-1, root)]
    mikrotik_section = None
    for indent, line in _clean_lines(content):
        if indent == 0 and line.startswith("/"):
            mikrotik_section = Node(line)
            root.children.append(mikrotik_section)
            stack = [(-1, root)]
            continue
        if indent == 0 and mikrotik_section is not None and not line.startswith("/"):
            mikrotik_section.children.append(Node(line))
            continue
        mikrotik_section = None
        while stack[-1][0] >= indent:
            stack.pop()
        node = Node(line)
        stack[-1][1].children.append(node)
        stack.append((indent, node))
    return root


def parse_config(content: str) -> Node:
    if _is_brace_style(content):
        return _parse_braces(content)
    return _parse_indent(content)


# --------------------------------------------------------------------------
# Helpers for keys and labels
# --------------------------------------------------------------------------

def _strip_quotes(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _split_negation(line: str) -> tuple[bool, str]:
    for prefix in NEGATIONS:
        if line.startswith(prefix):
            return True, line[len(prefix):]
    return False, line


def line_key(line: str) -> str:
    """Return the attribute a line sets, so that old and new values pair up."""
    _, body = _split_negation(line)
    tokens = body.split()
    if not tokens:
        return body
    for prefix in KEY_PREFIXES:
        if tuple(tokens[: len(prefix)]) == prefix:
            return " ".join(prefix)
    for index, token in enumerate(tokens):
        if token in VALUE_KEYWORDS:
            return " ".join(tokens[: index + 1])
    if tokens[0] == "set" and len(tokens) > 2:  # Fortinet "set attr value..."
        return " ".join(tokens[:2])
    if tokens[0] in ("add", "set") and any("=" in token for token in tokens):  # MikroTik
        for prefix in ("name=", "numbers=", "address=", "interface="):
            names = [token for token in tokens if token.startswith(prefix)]
            if names:
                return f"{tokens[0]} {names[0]}"
        return tokens[0]
    kv = [token.split("=", 1)[0] for token in tokens if "=" in token]
    if kv:
        return " ".join(tokens[:1] + kv)
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(tokens[:-1])


def _value(line: str, key: str) -> str:
    _, body = _split_negation(line)
    if body.startswith(key):
        return _strip_quotes(body[len(key):]) or body
    return body


def _attribute_label(key: str) -> str:
    plain = key[4:] if key.startswith("set ") else key
    for pattern, label in ATTRIBUTE_LABELS:
        if re.search(pattern, plain):
            return label
    return plain


def _describe_object(path: list[str]) -> tuple[str, str]:
    """Return (category, human name) of the object a section path points to."""
    joined = " ".join(path)
    for header in reversed(path):
        match = re.match(r"^interfaces?\s+(\S+)", header)
        if match:
            return "Interface", f"Interface {_strip_quotes(match.group(1))}"
        match = re.match(r"^vlan\s+(\d[\d,\-\s]*)$", header) or re.match(r"^vlans\s+(\S+)$", header)
        if match:
            return "VLAN", f"VLAN {_strip_quotes(match.group(1).strip())}"
    if len(path) >= 2 and path[0] in ("interfaces",):
        return "Interface", f"Interface {_strip_quotes(path[1])}"
    if len(path) >= 2 and path[0] == "vlans":
        return "VLAN", f"VLAN {_strip_quotes(path[1])}"
    if path and path[0] == "config system interface" and len(path) > 1:
        return "Interface", "Interface " + _strip_quotes(path[1].removeprefix("edit "))
    if path and path[0].startswith(("/interface vlan", "config vlan")):
        return "VLAN", " ".join(_strip_quotes(p) for p in path)
    if path and path[0].startswith("/interface"):
        return "Interface", " ".join(path)
    if path and re.match(r"^(router|protocols|ip route|routing-options)", joined):
        return "Routing", " > ".join(path)
    if path and re.match(r"^(ip access-list|access-list|acl|firewall|policy-options|config firewall)", joined):
        return "Security", " > ".join(path)
    if path:
        return "Section", " > ".join(path)
    return "System", "Global configuration"


def _summarise_section(node: Node) -> str:
    details = []
    for child in node.children:
        key = line_key(child.text)
        label = _attribute_label(key)
        if label in ("name", "description", "access VLAN", "IP address", "VLAN ID"):
            details.append(f"{label} {_value(child.text, key)}")
    return f" ({', '.join(details[:3])})" if details else ""


# --------------------------------------------------------------------------
# Tree comparison
# --------------------------------------------------------------------------

def _index(children: list[Node]) -> dict[str, Node]:
    index = {}
    for child in children:
        key = child.text
        counter = 2
        while key in index:
            key = f"{child.text}\x00{counter}"
            counter += 1
        index[key] = child
    return index


def _section_changes(path: list[str], old: list[Node], new: list[Node], out: list[Change]) -> None:
    old_index = _index(old)
    new_index = _index(new)
    removed = [node for key, node in old_index.items() if key not in new_index]
    added = [node for key, node in new_index.items() if key not in old_index]

    for key in old_index.keys() & new_index.keys():
        old_node, new_node = old_index[key], new_index[key]
        if old_node.children or new_node.children:
            _section_changes(path + [old_node.text], old_node.children, new_node.children, out)

    category, obj = _describe_object(path)

    # Sections (headers with children) that appear or disappear as a whole.
    for node in [n for n in removed if n.children]:
        sub_category, sub_obj = _describe_object(path + [node.text])
        out.append(Change("removed", sub_category, sub_obj, f"{sub_obj} removed{_summarise_section(node)}", old=node.text))
    for node in [n for n in added if n.children]:
        sub_category, sub_obj = _describe_object(path + [node.text])
        out.append(Change("added", sub_category, sub_obj, f"{sub_obj} added{_summarise_section(node)}", new=node.text))

    removed_lines = [n for n in removed if not n.children]
    added_lines = [n for n in added if not n.children]

    old_by_key: dict[str, list[Node]] = {}
    for node in removed_lines:
        old_by_key.setdefault(line_key(node.text), []).append(node)
    new_by_key: dict[str, list[Node]] = {}
    for node in added_lines:
        new_by_key.setdefault(line_key(node.text), []).append(node)

    paired = set()
    for key in old_by_key.keys() & new_by_key.keys():
        if len(old_by_key[key]) != 1 or len(new_by_key[key]) != 1:
            continue
        old_line, new_line = old_by_key[key][0].text, new_by_key[key][0].text
        paired.update({id(old_by_key[key][0]), id(new_by_key[key][0])})
        out.append(_modification(category, obj, key, old_line, new_line))

    for node in removed_lines:
        if id(node) not in paired:
            out.append(_single_line("removed", category, obj, node.text, path))
    for node in added_lines:
        if id(node) not in paired:
            out.append(_single_line("added", category, obj, node.text, path))


def _admin_state(line: str) -> bool | None:
    negated, body = _split_negation(line)
    if body in ADMIN_STATE:
        return negated  # "no shutdown" -> enabled
    if line in ("set status up", "enable"):
        return True
    return None


def _modification(category: str, obj: str, key: str, old_line: str, new_line: str) -> Change:
    old_state, new_state = _admin_state(old_line), _admin_state(new_line)
    if old_state is not None and new_state is not None:
        state = "enabled (no shutdown)" if new_state else "disabled (shutdown)"
        return Change("modified", category, obj, f"{obj}: administratively {state}", old_line, new_line)

    label = _attribute_label(key)
    old_neg, _ = _split_negation(old_line)
    new_neg, _ = _split_negation(new_line)
    if old_neg != new_neg:
        verb = "disabled" if new_neg else "enabled"
        return Change("modified", category, obj, f"{obj}: {label} {verb}", old_line, new_line)
    if "=" in old_line and "=" in new_line:  # MikroTik "add name=x vlan-id=10"
        old_kv = dict(token.split("=", 1) for token in old_line.split() if "=" in token)
        new_kv = dict(token.split("=", 1) for token in new_line.split() if "=" in token)
        diffs = [
            f'{name} changed "{old_kv.get(name, "")}" -> "{new_kv.get(name, "")}"'
            for name in sorted(old_kv.keys() | new_kv.keys())
            if old_kv.get(name) != new_kv.get(name)
        ]
        target = f"{obj} {key.split(' ', 1)[1]}" if " " in key else obj
        return Change("modified", category, target, f"{target}: {', '.join(diffs)}", old_line, new_line)
    old_value, new_value = _value(old_line, key), _value(new_line, key)
    if label == "hostname":
        return Change("modified", "System", "Hostname", f'Hostname changed "{old_value}" -> "{new_value}"', old_line, new_line)
    return Change("modified", category, obj, f'{obj}: {label} changed "{old_value}" -> "{new_value}"', old_line, new_line)


def _single_line(action: str, category: str, obj: str, line: str, path: list[str]) -> Change:
    state = _admin_state(line)
    old, new = (line, "") if action == "removed" else ("", line)
    if state is not None and path:
        # Adding "shutdown" disables the port, removing it enables it again.
        enabled = state if action == "added" else not state
        text = "enabled (no shutdown)" if enabled else "disabled (shutdown)"
        return Change("modified", category, obj, f"{obj}: administratively {text}", old, new)

    if not path:
        match = re.match(r"^vlan batch\s+(.+)$", line)
        if match:
            return Change(action, "VLAN", f"VLAN {match.group(1)}", f"VLAN batch {match.group(1)} {action}", old, new)
        match = re.match(r"^vlan\s+(\d+)", line)
        if match:
            return Change(action, "VLAN", f"VLAN {match.group(1)}", f"VLAN {match.group(1)} {action}", old, new)
        match = re.match(r"^interface\s+(\S+)", line)
        if match:
            return Change(action, "Interface", f"Interface {match.group(1)}", f"Interface {match.group(1)} {action}", old, new)
        match = re.match(r"^(?:set\s+)?(interfaces|vlans)\s+(\S+)\s+(.+)$", line)  # Junos / VyOS "set" style
        if match:
            kind = "Interface" if match.group(1) == "interfaces" else "VLAN"
            name = f"{kind} {_strip_quotes(match.group(2))}"
            return Change(action, kind, name, f"{name}: {action} \"{match.group(3)}\"", old, new)

    key = line_key(line)
    label = _attribute_label(key)
    if label != key:
        return Change(action, category, obj, f'{obj}: {label} {action} "{_value(line, key)}"', old, new)
    return Change(action, category, obj, f'{obj}: line {action} "{line}"', old, new)


def _collapse_set_style(root: Node) -> Node:
    """Group flat "set a b c ..." configurations (Junos/VyOS display set) by object."""
    lines = [child.text for child in root.children if not child.children]
    if not lines or sum(1 for line in lines if line.startswith(("set ", "delete "))) < len(lines) * 0.8:
        return root
    grouped = Node("")
    sections: dict[str, Node] = {}
    for child in root.children:
        tokens = child.text.split()
        if tokens and tokens[0] == "set" and len(tokens) > 3 and tokens[1] in ("interfaces", "vlans"):
            header = f"{tokens[1]} {tokens[2]}"
            section = sections.get(header)
            if section is None:
                section = sections[header] = Node(header)
                grouped.children.append(section)
            section.children.append(Node(" ".join(tokens[3:])))
        else:
            grouped.children.append(child)
    return grouped


def compare(old_content: str, new_content: str) -> list[Change]:
    old_tree = _collapse_set_style(parse_config(old_content))
    new_tree = _collapse_set_style(parse_config(new_content))
    changes: list[Change] = []
    _section_changes([], old_tree.children, new_tree.children, changes)
    order = {"System": 0, "Interface": 1, "VLAN": 2, "Routing": 3, "Security": 4, "Section": 5}
    changes.sort(key=lambda change: (order.get(change.category, 9), change.obj))
    return changes


def summary(changes: list[Change]) -> dict[str, int]:
    counts = {"added": 0, "removed": 0, "modified": 0}
    for change in changes:
        counts[change.action] += 1
    return counts
