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

import hashlib
import re
import xml.etree.ElementTree as ElementTree
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
    ("snmp-server", "community"),
    ("snmp-agent", "community"),
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
    (r"(^| )(description|comments?|descr)$", "description"),
    (r"^type$", "action"),
    (r"(^| )alias$", "alias"),
    (r"(^| )members$", "VLAN members"),
    (r"(^| )name$", "name"),
    (r"^(hostname|sysname|host-name)$", "hostname"),
    (r"(switchport access vlan|port default vlan|vlan access)$", "access VLAN"),
    (r"(trunk allowed vlan|allow-pass vlan|vlan trunk allowed|vlan members)", "allowed VLANs"),
    (r"(native vlan|native-vlan-id|pvid vlan|vlan trunk native)", "native VLAN"),
    (r"(switchport mode|port link-type|port-mode|interface-mode)", "port mode"),
    (r"general allowed vlan untagged$", "untagged VLANs"),
    (r"general allowed vlan tagged$", "tagged VLANs"),
    (r"(^| )pvid$", "native VLAN (PVID)"),
    (r"^vlan tagging$", "tagged VLANs"),
    (r"^vlan participation include$", "member VLANs"),
    (r"^vlan participation exclude$", "excluded VLANs"),
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
    display: str = ""  # human name of a section (pfSense rules are keyed by tracker id)
    key: str = ""  # attribute key of a leaf when known (XML tag)


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


BLOCK_OPENER = re.compile(r"^(interface\s|vlan database$|router\s|line\s|ip\s+routing|policy-map\s|class-map\s)")


def _indent_exit_blocks(content: str) -> str:
    """Indent flat blocks that are closed by "exit" (Ubiquiti EdgeSwitch, FASTPATH).

    A block is an unindented opener (e.g. "interface 0/1") followed by
    unindented lines up to an unindented "exit" with no other opener in between.
    """
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    result = []
    index = 0
    while index < len(lines):
        line = lines[index]
        result.append(line)
        if line[:1].strip() and BLOCK_OPENER.match(line):
            end = index + 1
            while end < len(lines):
                candidate = lines[end]
                if candidate.strip() == "exit" and not candidate[:1].isspace():
                    break
                if candidate[:1].strip() and BLOCK_OPENER.match(candidate):
                    end = len(lines)
                    break
                end += 1
            if end < len(lines):
                result.extend(" " + child if child.strip() else child for child in lines[index + 1 : end])
                index = end
        index += 1
    return "\n".join(result)


# --------------------------------------------------------------------------
# pfSense / OPNsense config.xml
# --------------------------------------------------------------------------

XML_ROOTS = ("pfsense", "opnsense")
# Child elements that identify an entry in a list (firewall rules, VLANs, users ...).
XML_ID_FIELDS = ("tracker", "vlanif", "name", "network", "refid", "uuid", "id")
# Values that must never be shown; they are replaced by a short fingerprint so a
# change is still detected.
XML_SECRET_TAGS = {
    "bcrypt-hash", "sha512-hash", "md5-hash", "password", "passwd", "prv", "key", "tls", "shared_key",
    "pre-shared-key", "psk", "secret", "authorizedkeys", "radius_secret", "radius_secret2", "ldap_bindpw",
    "rocommunity", "rwcommunity", "community", "apikey", "privkey",
}
XML_IGNORED_TAGS = {"revision", "lastchange", "version"}


def _fingerprint(value: str) -> str:
    return "*****#" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _xml_children(element) -> list[Node]:
    counts: dict[str, int] = {}
    for child in element:
        counts[child.tag] = counts.get(child.tag, 0) + 1

    nodes = []
    for child in element:
        tag = child.tag
        if not isinstance(tag, str) or tag in XML_IGNORED_TAGS:
            continue
        if len(child) == 0:
            text = (child.text or "").strip()
            if tag in XML_SECRET_TAGS and text:
                text = _fingerprint(text)
            elif len(text) > 200:  # certificates and other blobs
                text = _fingerprint(text)
            nodes.append(Node(f"{tag} {text}".strip(), key=tag))
            continue

        values = {grand.tag: (grand.text or "").strip() for grand in child if len(grand) == 0}
        identifier = ""
        if tag not in ("source", "destination"):
            identifier = next((values[name] for name in XML_ID_FIELDS if values.get(name)), "")
        if not identifier and counts[tag] > 1:
            identifier = values.get("descr", "")
        header = f"{tag} {identifier}".strip()

        descr = values.get("descr", "")
        if tag == "vlan" and values.get("tag"):
            display = f"vlan {values['tag']}" + (f" ({values['if']})" if values.get("if") else "")
        elif tag in ("user", "group") or not descr or descr == identifier:
            display = header
        elif identifier:
            display = f'{tag} "{descr}"'
        else:
            display = f"{header} ({descr})"
        nodes.append(Node(header, _xml_children(child), display))
    return nodes


def _parse_xml(content: str) -> Node | None:
    stripped = content.lstrip()
    if not stripped.startswith("<") or "<!ENTITY" in content or "<!DOCTYPE" in content:
        return None
    try:
        root = ElementTree.fromstring(stripped.encode("utf-8"))
    except ElementTree.ParseError:
        return None
    if root.tag not in XML_ROOTS:
        return None
    return Node("", _xml_children(root))


def config_author(content: str) -> str:
    """Who saved the configuration (pfSense/OPNsense <revision>), if known."""
    stripped = (content or "").lstrip()
    if not stripped.startswith("<") or "<!ENTITY" in content or "<!DOCTYPE" in content:
        return ""
    try:
        root = ElementTree.fromstring(stripped.encode("utf-8"))
    except ElementTree.ParseError:
        return ""
    revision = root.find("revision")
    if revision is None:
        return ""
    username = (revision.findtext("username") or "").strip()
    description = (revision.findtext("description") or "").strip()
    if username and description.startswith(username):
        description = description[len(username):].lstrip(" :")
    return ": ".join(part for part in (username, description) if part)


def parse_config(content: str) -> Node:
    xml_tree = _parse_xml(content)
    if xml_tree is not None:
        return xml_tree
    if _is_brace_style(content):
        return _parse_braces(content)
    return _parse_indent(_indent_exit_blocks(content))


# --------------------------------------------------------------------------
# Helpers for keys and labels
# --------------------------------------------------------------------------

def _strip_quotes(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _key_values(line: str, raw: bool = False) -> dict[str, str]:
    """Parse MikroTik style key=value pairs; quoted values may contain spaces."""
    pairs = re.findall(r'([\w.-]+)=("[^"]*"|\S+)', line)
    return {key: value if raw else _strip_quotes(value) for key, value in pairs}


def _split_negation(line: str) -> tuple[bool, str]:
    for prefix in NEGATIONS:
        if line.startswith(prefix):
            return True, line[len(prefix):]
    return False, line


VLAN_NAME_LINE = (
    re.compile(r"^vlan\s+(?P<vlan>\d[\d,\-]*)\s+name\s+(?P<name>.+)$"),  # Allied Telesis
    re.compile(r"^vlan\s+name\s+(?P<vlan>\d+)\s+(?P<name>.+)$"),  # Ubiquiti EdgeSwitch
)


# "switchport general allowed vlan add 1411 untagged" (Aruba Instant On 1930 and
# similar general-mode switches): the attribute is the tagged/untagged list.
GENERAL_ALLOWED_VLAN = re.compile(r"^switchport\s+general\s+allowed\s+vlan\s+(?:add\s+)?(?P<vlans>\S+)\s+(?P<mode>tagged|untagged)$")
VLAN_LIST = re.compile(r"^\[?\s*\d+(?:-\d+)?(?:\s*[,\s]\s*\d+(?:-\d+)?)*\s*\]?$")


def _expand_vlans(value: str) -> set[int] | None:
    value = value.strip().strip("[]").strip()
    if not value or not VLAN_LIST.match(value):
        return None
    vlans: set[int] = set()
    for part in re.split(r"[,\s]+", value):
        if not part:
            continue
        if "-" in part:
            start, end = (int(bound) for bound in part.split("-", 1))
            if end < start or end - start > 4094:
                return None
            vlans.update(range(start, end + 1))
        else:
            vlans.add(int(part))
    return vlans


def _compact_vlans(vlans: set[int]) -> str:
    ranges = []
    for vlan in sorted(vlans):
        if ranges and vlan == ranges[-1][1] + 1:
            ranges[-1][1] = vlan
        else:
            ranges.append([vlan, vlan])
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


def _vlan_delta(old_value: str, new_value: str) -> str:
    old_vlans, new_vlans = _expand_vlans(old_value), _expand_vlans(new_value)
    if old_vlans is None or new_vlans is None or (len(old_vlans) <= 1 and len(new_vlans) <= 1):
        return ""
    parts = []
    if new_vlans - old_vlans:
        parts.append(f"added {_compact_vlans(new_vlans - old_vlans)}")
    if old_vlans - new_vlans:
        parts.append(f"removed {_compact_vlans(old_vlans - new_vlans)}")
    return f" ({'; '.join(parts)})" if parts else ""


def _vlan_name_line(line: str):
    for pattern in VLAN_NAME_LINE:
        match = pattern.match(line)
        if match:
            return match.group("vlan"), _strip_quotes(match.group("name"))
    return None


def line_key(line: str) -> str:
    """Return the attribute a line sets, so that old and new values pair up."""
    vlan_name = _vlan_name_line(line)
    if vlan_name:
        return f"vlan {vlan_name[0]} name"
    general = GENERAL_ALLOWED_VLAN.match(line)
    if general:
        return f"switchport general allowed vlan {general.group('mode')}"
    user = re.match(r"^(?:no\s+)?(username|local-user|user)\s+(\S+)", line)
    if user:
        return f"{user.group(1)} {user.group(2)}"
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
    if tokens[0] in ("add", "set") and any("=" in token for token in tokens):  # MikroTik
        if tokens[0] == "set" and len(tokens) > 1 and "=" not in tokens[1]:
            return f"set {tokens[1]}"  # "set 3 disabled=yes", "set ether1 comment=x"
        for prefix in ("name=", "numbers=", "vlan-ids=", "address=", "interface="):
            names = [token for token in tokens if token.startswith(prefix)]
            if names:
                return f"{tokens[0]} {names[0]}"
        if tokens[0] == "set":
            return "set " + " ".join(token.split("=", 1)[0] for token in tokens[1:] if "=" in token)
        return tokens[0]
    if tokens[0] == "set" and len(tokens) > 2:  # Fortinet "set attr value..."
        return " ".join(tokens[:2])
    kv = [token.split("=", 1)[0] for token in tokens if "=" in token]
    if kv:
        return " ".join(tokens[:1] + kv)
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(tokens[:-1])


def _value(line: str, key: str) -> str:
    general = GENERAL_ALLOWED_VLAN.match(line)
    if general:
        return general.group("vlans")
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
        match = re.match(r"^interface\s+vlan\s*(\d+)$", header, re.IGNORECASE)
        if match:
            return "VLAN", f"VLAN {match.group(1)} (interface)"
        match = re.match(r"^interfaces?\s+(\S+)", header)
        if match:
            return "Interface", f"Interface {_strip_quotes(match.group(1))}"
        match = re.match(r"^vlan\s+(\d[\d,\-\s]*)$", header) or re.match(r"^vlans\s+(\S+)$", header)
        if match:
            return "VLAN", f"VLAN {_strip_quotes(match.group(1).strip())}"
    # pfSense / OPNsense (config.xml)
    if path and path[0] in ("filter", "nat"):
        kind = "Firewall" if path[0] == "filter" else "NAT"
        return "Security", " > ".join([kind] + path[1:])
    if path and path[0] == "aliases" and len(path) > 1:
        return "Security", "Firewall alias " + path[1].removeprefix("alias ").strip('"')
    if path and path[0] in ("openvpn", "ipsec", "wireguard"):
        return "Security", " > ".join(path)
    if len(path) >= 2 and path[0] == "system" and path[1].startswith(("user ", "group ")):
        kind, _, name = path[1].partition(" ")
        return "System", f"{'User' if kind == 'user' else 'Group'} {name.strip(chr(34))}"
    if path and path[0] in ("staticroutes", "gateways"):
        return "Routing", " > ".join(path)
    if len(path) >= 2 and path[0] == "vlans":
        match = re.match(r"^vlan (\d+)(.*)$", path[1])
        if match:
            return "VLAN", f"VLAN {match.group(1)}{match.group(2)}"
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
        key = child.key or line_key(child.text)
        label = _attribute_label(key)
        if label in ("name", "description", "access VLAN", "IP address", "VLAN ID", "action", "interface"):
            details.append(f"{label} {_value(child.text, key)}")
    if not details:
        # Unknown section: show its first lines so the reader knows what was added.
        lines = [child.text for child in node.children if not child.children][:2]
        if lines:
            more = len(node.children) - len(lines)
            return f" ({'; '.join(lines)}" + (f"; +{more} more" if more > 0 else "") + ")"
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
            _section_changes(path + [new_node.display or new_node.text], old_node.children, new_node.children, out)

    category, obj = _describe_object(path)

    # Sections (headers with children) that appear or disappear as a whole.
    for node in [n for n in removed if n.children]:
        sub_category, sub_obj = _describe_object(path + [node.display or node.text])
        out.append(Change("removed", sub_category, sub_obj, f"{sub_obj} removed{_summarise_section(node)}", old=node.text))
    for node in [n for n in added if n.children]:
        sub_category, sub_obj = _describe_object(path + [node.display or node.text])
        out.append(Change("added", sub_category, sub_obj, f"{sub_obj} added{_summarise_section(node)}", new=node.text))

    removed_lines = [n for n in removed if not n.children]
    added_lines = [n for n in added if not n.children]

    old_by_key: dict[str, list[Node]] = {}
    for node in removed_lines:
        old_by_key.setdefault(node.key or line_key(node.text), []).append(node)
    new_by_key: dict[str, list[Node]] = {}
    for node in added_lines:
        new_by_key.setdefault(node.key or line_key(node.text), []).append(node)

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

    old_vlan_name, new_vlan_name = _vlan_name_line(old_line), _vlan_name_line(new_line)
    if old_vlan_name and new_vlan_name:
        vlan = new_vlan_name[0]
        return Change("modified", "VLAN", f"VLAN {vlan}", f'VLAN {vlan}: name changed "{old_vlan_name[1]}" -> "{new_vlan_name[1]}"', old_line, new_line)

    if re.match(r"^(username|local-user|user) \S+$", key):
        name = key.split(" ", 1)[1]
        return Change("modified", "System", f"User {name}", f"User {name} changed (password, privilege or other settings)", old_line, new_line)

    old_list = re.match(r"^vlan\s+(\d[\d,\-]*)$", old_line)
    new_list = re.match(r"^vlan\s+(\d[\d,\-]*)$", new_line)
    if old_list and new_list and obj == "vlan database":
        delta = _vlan_delta(old_list.group(1), new_list.group(1))
        return Change("modified", "VLAN", "VLAN list", f'VLAN list changed "{old_list.group(1)}" -> "{new_list.group(1)}"{delta}', old_line, new_line)

    label = _attribute_label(key)
    old_neg, _ = _split_negation(old_line)
    new_neg, _ = _split_negation(new_line)
    if old_neg != new_neg:
        verb = "disabled" if new_neg else "enabled"
        return Change("modified", category, obj, f"{obj}: {label} {verb}", old_line, new_line)
    if "=" in old_line and "=" in new_line:  # MikroTik "add name=x vlan-id=10"
        old_kv = _key_values(old_line)
        new_kv = _key_values(new_line)
        diffs = []
        for name in sorted(old_kv.keys() | new_kv.keys()):
            if old_kv.get(name) == new_kv.get(name):
                continue
            if re.search(r"(password|secret|key|psk|passphrase|community)", name, re.IGNORECASE):
                diffs.append(f"{name} changed")
            elif name not in old_kv:
                diffs.append(f'{name} set to "{new_kv[name]}"')
            elif name not in new_kv:
                diffs.append(f"{name} unset")
            else:
                diffs.append(f'{name} changed "{old_kv[name]}" -> "{new_kv[name]}"')
        item = key.split(" ", 1)[1] if " " in key else ""
        # "set 3 disabled=yes" -> item "3"; "set show-at-login=yes" -> item is an attribute, not an entry
        target = obj if not item or f"{item.split()[0]}=" in old_line else f"{obj} [{item}]"
        vlan = new_kv.get("vlan-ids") or new_kv.get("vlan-id")
        if vlan and old_kv.get("vlan-ids", old_kv.get("vlan-id")) == vlan:
            category, target = "VLAN", f"VLAN {vlan}"
        return Change("modified", category, target, f"{target}: {'; '.join(diffs)}", old_line, new_line)
    old_value, new_value = _value(old_line, key), _value(new_line, key)
    if label == "hostname":
        return Change("modified", "System", "Hostname", f'Hostname changed "{old_value}" -> "{new_value}"', old_line, new_line)
    delta = _vlan_delta(old_value, new_value) if "vlan" in key.lower() or "VLAN" in label else ""
    return Change("modified", category, obj, f'{obj}: {label} changed "{old_value}" -> "{new_value}"{delta}', old_line, new_line)


def _single_line(action: str, category: str, obj: str, line: str, path: list[str]) -> Change:
    state = _admin_state(line)
    old, new = (line, "") if action == "removed" else ("", line)
    if state is not None and path:
        # Adding "shutdown" disables the port, removing it enables it again.
        enabled = state if action == "added" else not state
        text = "enabled (no shutdown)" if enabled else "disabled (shutdown)"
        return Change("modified", category, obj, f"{obj}: administratively {text}", old, new)

    vlan_name = _vlan_name_line(line)
    if vlan_name:
        return Change(action, "VLAN", f"VLAN {vlan_name[0]}", f'VLAN {vlan_name[0]} {action} (name "{vlan_name[1]}")', old, new)
    if path and path[-1] == "vlan database":
        match = re.match(r"^vlan\s+(\d[\d,\-]*)$", line)
        if match:
            return Change(action, "VLAN", f"VLAN {match.group(1)}", f"VLAN list {match.group(1)} {action}", old, new)

    user = re.match(r"^(?:username|local-user)\s+(\S+)", line)
    if user:
        return Change(action, "System", f"User {user.group(1)}", f"User {user.group(1)} {action}", old, new)

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

    kv = _key_values(line, raw=True)
    vlan = kv.get("vlan-ids") or kv.get("vlan-id")
    if vlan:  # MikroTik "/interface bridge vlan" or "/interface vlan" entry
        details = [
            f"{name} {kv[name]}"
            for name in ("name", "bridge", "interface", "tagged", "untagged", "comment")
            if name in kv
        ]
        suffix = f" ({', '.join(details)})" if details else ""
        return Change(action, "VLAN", f"VLAN {vlan}", f"VLAN {vlan} {action}{suffix}", old, new)

    tokens = line.split()
    if kv and path and path[0].startswith("/") and tokens[0] == "set":
        # MikroTik "set 0 action=remote" / "set show-at-login=yes": describe the values that were set
        item = f" [{tokens[1]}]" if len(tokens) > 1 and "=" not in tokens[1] else ""
        values = _key_values(line)
        if action == "added":
            parts = [
                f"{name} changed" if re.search(r"(password|secret|key|psk|passphrase|community)", name, re.IGNORECASE)
                else f'{name} set to "{value}"'
                for name, value in values.items()
            ]
        else:
            parts = [f"{name} unset" for name in values]
        return Change("modified", category, obj, f"{obj}{item}: {'; '.join(parts)}", old, new)

    key = line_key(line)
    label = _attribute_label(key)
    if label != key and not kv:
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
    changes.sort(key=lambda change: (order.get(change.category, 9), change.obj, change.message))
    return changes


def summary(changes: list[Change]) -> dict[str, int]:
    counts = {"added": 0, "removed": 0, "modified": 0}
    for change in changes:
        counts[change.action] += 1
    return counts
