#!/usr/bin/env python3
"""Extract protocol field metadata without executing Cursor's JavaScript."""

import argparse
import hashlib
import json
import plistlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = "Contents/Resources/app/out/vs/workbench/workbench.desktop.main.js"
OUTPUT = ROOT / "internal/integrations/cursor/schema.json"
ROOT_TYPE = "aiserver.v1.RunInferenceClientMessage"
AUXILIARY_OUTPUT = ROOT / "internal/integrations/cursor/auxiliary-schema.json"
AUXILIARY_ROOTS = (
    "aiserver.v1.NameTabRequest",
    "agent.v1.UpdateConversationMetadataRequest",
    "aiserver.v1.ClassifyAgentAutoReviewRequest",
    "aiserver.v1.StreamCppRequest",
)
AGENT_OUTPUT = ROOT / "internal/integrations/cursor/agent-schema.json"
# Snapshot complete descriptors for reviewed message types, not the entire
# transitive Agent protocol. Field permissions are separately owned by Go.
AGENT_ROOTS = tuple(
    "agent.v1." + name
    for name in (
        "AgentClientMessage",
        "AgentRunRequest",
        "ConversationStateStructure",
        "ConversationAction",
        "UserMessageAction",
        "ResumeAction",
        "CancelAction",
        "UserMessage",
        "SelectedContext",
        "ExtraContextEntry",
        "SelectedFile",
        "SelectedCodeSelection",
        "SelectedTerminal",
        "SelectedTerminalSelection",
        "SelectedCursorRule",
        "SelectedCursorCommand",
        "Range",
        "Position",
        "CursorRule",
        "CursorRuleType",
        "CursorRuleTypeGlobal",
        "CursorRuleTypeFileGlobs",
        "CursorRuleTypeAgentFetched",
        "CursorRuleTypeManuallyAttached",
        "RequestContext",
        "RequestContextEnv",
        "ModelDetails",
        "ThinkingDetails",
        "RequestedModel",
        "RequestedModel.ModelParameterValue",
        "McpTools",
        "McpToolDefinition",
        "ExecClientMessage",
        "ExecClientControlMessage",
        "ExecClientStreamClose",
        "ExecClientHeartbeat",
        "ExecClientThrow",
        "ClientHeartbeat",
        "HookAdditionalContext",
        "ShellResult",
        "ShellSuccess",
        "ShellFailure",
        "ShellTimeout",
        "ShellRejected",
        "ShellSpawnError",
        "ShellPermissionDenied",
        "OutputLocation",
        "ReadResult",
        "ReadSuccess",
        "ReadError",
        "ReadRejected",
        "ReadFileNotFound",
        "ReadPermissionDenied",
        "ReadInvalidFile",
        "WriteResult",
        "WriteSuccess",
        "WritePermissionDenied",
        "WriteNoSpace",
        "WriteError",
        "WriteRejected",
        "DeleteResult",
        "DeleteSuccess",
        "DeleteFileNotFound",
        "DeleteNotFile",
        "DeletePermissionDenied",
        "DeleteFileBusy",
        "DeleteRejected",
        "DeleteError",
        "McpResult",
        "McpSuccess",
        "McpToolResultContentItem",
        "McpTextContent",
        "McpError",
        "McpRejected",
        "McpPermissionDenied",
        "McpToolNotFound",
        "McpServerNotFound",
        "McpApproved",
        "SystemReminder",
        "PreFetchedBlob",
        "PrewarmRequest",
        "ConversationTurnStructure",
        "AgentConversationTurnStructure",
        "ShellConversationTurnStructure",
        "ConversationStep",
        "AssistantMessage",
        "ThinkingMessage",
        "TodoItem",
        "ConversationSummary",
        "ConversationPlan",
        "ShellCommand",
        "ShellOutput",
        "RequestContextResult",
        "RequestContextSuccess",
        "RequestContextError",
        "RequestContextRejected",
        "GitRepoInfo",
        "RepositoryIndexingInfo",
        "McpInstructions",
        "AgentSkill",
        "SkillOptions",
        "SkillDescriptor",
        "CustomSubagent",
        "HooksConfigInfo",
        "PermissionsAutoRunInstructions",
        "LsDirectoryTreeNode",
        "LsDirectoryTreeNode.File",
        "TerminalMetadata",
        "TerminalMetadata.Command",
        "GrepResult",
        "GrepSuccess",
        "GrepUnionResult",
        "GrepContentResult",
        "GrepFileMatch",
        "GrepContentMatch",
        "GrepFilesResult",
        "GrepCountResult",
        "GrepFileCount",
        "GrepError",
        "LsResult",
        "LsSuccess",
        "LsError",
        "LsRejected",
        "LsTimeout",
        "DiagnosticsResult",
        "DiagnosticsSuccess",
        "Diagnostic",
        "DiagnosticsError",
        "DiagnosticsRejected",
        "DiagnosticsFileNotFound",
        "DiagnosticsPermissionDenied",
        "ToolCall",
        "ShellToolCall",
        "ShellArgs",
        "ShellCommandParsingResult",
        "ShellCommandParsingResult.ExecutableCommand",
        "ShellCommandParsingResult.ExecutableCommandArg",
        "ShellCommandParsingResult.Redirect",
        "CommandClassifierResult",
        "CommandClassifierResult.ClassifiedCommand",
        "ShellOutputNotificationConfig",
        "ShellHookApprovalRequirement",
        "SmartModeApproval",
        "SandboxPolicy",
        "NetworkPolicy",
        "NetworkPolicyLoggingConfig",
        "ReadToolCall",
        "ReadToolArgs",
        "ReadToolResult",
        "ReadToolSuccess",
        "ReadToolError",
        "ReadRange",
        "EditToolCall",
        "EditArgs",
        "EditResult",
        "EditSuccess",
        "EditError",
        "EditFileNotFound",
        "EditReadPermissionDenied",
        "EditWritePermissionDenied",
        "EditRejected",
        "DeleteToolCall",
        "DeleteArgs",
        "GlobToolCall",
        "GlobToolArgs",
        "GlobToolResult",
        "GlobToolSuccess",
        "GlobToolError",
        "GrepToolCall",
        "GrepArgs",
        "LsToolCall",
        "LsArgs",
        "McpToolCall",
        "McpArgs",
        "McpToolResult",
        "McpToolError",
        "McpSymbolicPathArgument",
        "UpdateTodosToolCall",
        "UpdateTodosArgs",
        "UpdateTodosResult",
        "UpdateTodosSuccess",
        "UpdateTodosError",
        "ReadTodosToolCall",
        "ReadTodosArgs",
        "ReadTodosResult",
        "ReadTodosSuccess",
        "ReadTodosError",
        "ReadLintsToolCall",
        "ReadLintsToolArgs",
        "ReadLintsToolResult",
        "ReadLintsToolSuccess",
        "ReadLintsToolError",
        "FileDiagnostics",
        "DiagnosticItem",
        "DiagnosticRange",
    )
)
SCALARS = {
    1: "double",
    2: "float",
    3: "int64",
    4: "uint64",
    5: "int32",
    6: "fixed64",
    7: "fixed32",
    8: "bool",
    9: "string",
    12: "bytes",
    13: "uint32",
    15: "sfixed32",
    16: "sfixed64",
    17: "sint32",
    18: "sint64",
}


def literal(source):
    """Read only the generated descriptor literal grammar, never JavaScript."""
    source = re.sub(r"[\w$]+\.getEnumType\(([\w$]+)\)", r'"\1"', source)
    source = re.sub(r"([,{])([A-Za-z_]\w*):", r'\1"\2":', source)
    source = source.replace("!0", "true").replace("!1", "false")
    source = re.sub(
        r'("T":)([\w$]+)(?=[,}])',
        lambda m: m[1] + (m[2] if m[2].isdigit() else json.dumps(m[2])),
        source,
    )
    return json.loads(source)


def descriptor_array(source, start):
    """Find the closing array, including descriptors with a localName option."""
    depth, quoted, escaped = 1, False, False
    for index in range(start, len(source)):
        char = source[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return "[" + source[start:index] + "]"
    raise ValueError("unterminated generated descriptor array")


def extract(app, roots=(ROOT_TYPE,), *, transitive=True):
    version = plistlib.loads((app / "Contents/Info.plist").read_bytes())[
        "CFBundleShortVersionString"
    ]
    data = (app / BUNDLE).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    source = data.decode("utf-8")
    definitions = {}
    for match in re.finditer(
        r'([\w$]+)=[\w$]+\.makeMessageType\("([^"]+)",(?:\(\)=>)?\[', source
    ):
        definitions[match[1]] = (
            match[2],
            descriptor_array(source, match.end()),
        )
    for match in re.finditer(
        r'([\w$]+)\.typeName="(google\.protobuf\.[^"]+)",'
        r"\1\.fields=[\w$]+\.util\.newFieldList\(\(\)=>\[",
        source,
    ):
        definitions[match[1]] = (
            match[2],
            descriptor_array(source, match.end()),
        )
    enums = {}
    for match in re.finditer(r'([\w$]+)=[\w$]+\.makeEnum\("([^"]+)",\[', source):
        enums[match[1]] = (
            match[2],
            descriptor_array(source, match.end()),
        )
    for match in re.finditer(
        r'[\w$]+\.util\.setEnumType\(([\w$]+),"([^"]+)",\[', source
    ):
        enums[match[1]] = (
            match[2],
            descriptor_array(source, match.end()),
        )
    types, selected_enums = {}, {}

    def definition(symbol):
        if symbol not in definitions:
            # Minifier aliases may change between releases. Resolve declarations
            # to known message types, without evaluating code or hardcoding names.
            targets = {
                match[1]
                for match in re.finditer(
                    r"(?<![\w$])" + re.escape(symbol) + r"=([\w$]+)(?=[,;}])",
                    source,
                )
                if match[1] in definitions
            }
            if len(targets) != 1:
                raise ValueError(
                    f"cannot resolve generated protobuf message alias: {symbol}"
                )
            definitions[symbol] = definitions[targets.pop()]
        return definitions[symbol]

    def field_type(field):
        kind, value = field["kind"], field["T"]
        if kind == "scalar":
            return SCALARS[value]
        if kind == "message":
            if transitive:
                visit(value)
            return definition(value)[0]
        if kind == "enum":
            name, raw = enums[value]
            selected_enums[name] = sorted(item["no"] for item in literal(raw))
            return name
        raise ValueError("unsupported descriptor kind")

    def visit(symbol):
        name, raw = definition(symbol)
        if name in types:
            return
        types[name] = []
        for field in literal(raw):
            if set(field) - {
                "no",
                "name",
                "kind",
                "T",
                "K",
                "V",
                "repeated",
                "oneof",
                "opt",
            }:
                raise ValueError("unsupported descriptor property")
            number = int(field["no"])
            if (
                isinstance(field["no"], bool)
                or number != field["no"]
                or not 0 < number < 1 << 29
            ):
                raise ValueError("invalid protobuf field number")
            item = {"number": number, "name": field["name"]}
            if field["kind"] == "map":
                item["type"] = field_type(field["V"])
                item["map_key"] = SCALARS[field["K"]]
            else:
                item["type"] = field_type(field)
            for key in ("repeated", "oneof", "opt"):
                if key in field:
                    item[key] = field[key]
            types[name].append(item)

    for root in roots:
        symbols = [key for key, value in definitions.items() if value[0] == root]
        if not symbols:
            if root == roots[0]:
                raise ValueError("missing generated root message")
            # An older editor need not implement every newer auxiliary RPC.
            continue
        visit(symbols[0])
    result = {
        "cursor_version": version,
        "bundle": BUNDLE,
        "bundle_sha256": digest,
        "root": roots[0],
        "enums": dict(sorted(selected_enums.items())),
        "messages": dict(sorted(types.items())),
    }
    # One descriptor per line keeps wire numbers and semantics reviewable.
    lines = ["{"]
    for key, value in result.items():
        if key != "messages":
            lines.append(f"  {json.dumps(key)}: {json.dumps(value, sort_keys=True)},")
            continue
        lines.append('  "messages": {')
        for index, (name, fields) in enumerate(value.items()):
            lines.append(f"    {json.dumps(name)}: [")
            for n, field in enumerate(fields):
                suffix = "," if n + 1 < len(fields) else ""
                lines.append("      " + json.dumps(field) + suffix)
            lines.append("    ]" + ("," if index + 1 < len(value) else ""))
        lines.append("  }")
    return "\n".join([*lines, "}", ""])


def compatible(baseline, candidate):
    """Older subsets and unchanged schemas do not depend on version strings."""
    if baseline["root"] != candidate["root"]:
        return False
    for name, fields in candidate["messages"].items():
        known = {field["number"]: field for field in baseline["messages"].get(name, [])}
        if any(known.get(field["number"]) != field for field in fields):
            return False
    return all(
        set(values) <= set(baseline["enums"].get(name, []))
        for name, values in candidate["enums"].items()
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=Path("/Applications/Cursor.app"))
    parser.add_argument("--check", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--auxiliary", action="store_true")
    group.add_argument("--agent", action="store_true")
    args = parser.parse_args()
    try:
        output = AUXILIARY_OUTPUT if args.auxiliary else OUTPUT
        roots = AUXILIARY_ROOTS if args.auxiliary else (ROOT_TYPE,)
        if args.agent:
            output, roots = AGENT_OUTPUT, AGENT_ROOTS
        content = extract(args.app, roots, transitive=not args.agent)
        metadata = json.loads(content)
        if args.check:
            baseline = json.loads(output.read_text(encoding="utf-8"))
            if not compatible(baseline, metadata):
                raise ValueError("Cursor protocol differs from the reviewed schema")
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
    except (OSError, ValueError, KeyError, StopIteration) as error:
        parser.exit(1, f"Schema extraction failed: {error}\n")
    version = metadata["cursor_version"]
    print(f"Cursor {version}: schema {'compatible' if args.check else 'extracted'}.")


if __name__ == "__main__":
    main()
