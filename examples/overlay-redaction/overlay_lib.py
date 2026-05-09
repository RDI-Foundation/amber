#!/usr/bin/env python3

import http.server
import json
import socketserver
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, TypedDict


class RequestParseError(ValueError):
    pass


def require_object(raw: Any, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RequestParseError(f"{context} must be an object")
    return raw


def require_int(raw: dict[str, Any], key: str, context: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise RequestParseError(f"{context}.{key} must be an integer")
    return value


def require_str(raw: dict[str, Any], key: str, context: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise RequestParseError(f"{context}.{key} must be a string")
    return value


@dataclass(frozen=True)
class Capability:
    kind: str
    profile: str | None

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Capability":
        raw = require_object(raw, "capability")
        return cls(kind=raw.get("kind", ""), profile=raw.get("profile"))


@dataclass(frozen=True)
class Component:
    id: int
    parent: int | None
    moniker: str
    digest: str
    config: Any
    config_schema: Any
    program: dict[str, Any] | None
    slots: dict[str, Any]
    provides: dict[str, Any]
    resources: dict[str, Any]
    metadata: Any
    children: list[int]

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Component":
        raw = require_object(raw, "component")
        parent = raw.get("parent")
        if parent is not None and not isinstance(parent, int):
            raise RequestParseError("component.parent must be an integer")
        program = raw.get("program")
        if program is not None and not isinstance(program, dict):
            raise RequestParseError("component.program must be an object")
        slots = raw.get("slots", {})
        if not isinstance(slots, dict):
            raise RequestParseError("component.slots must be an object")
        provides = raw.get("provides", {})
        if not isinstance(provides, dict):
            raise RequestParseError("component.provides must be an object")
        resources = raw.get("resources", {})
        if not isinstance(resources, dict):
            raise RequestParseError("component.resources must be an object")
        children = raw.get("children", [])
        if not isinstance(children, list) or any(not isinstance(item, int) for item in children):
            raise RequestParseError("component.children must be a list of integers")
        return cls(
            id=require_int(raw, "id", "component"),
            parent=parent,
            moniker=raw.get("moniker", ""),
            digest=raw.get("digest", ""),
            config=raw.get("config"),
            config_schema=raw.get("config_schema"),
            program=program,
            slots=slots,
            provides=provides,
            resources=resources,
            metadata=raw.get("metadata"),
            children=children,
        )


@dataclass(frozen=True)
class SlotRef:
    component_id: int
    slot: str

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "SlotRef":
        raw = require_object(raw, "slot ref")
        return cls(
            component_id=require_int(raw, "component", "slot ref"),
            slot=require_str(raw, "name", "slot ref"),
        )


@dataclass(frozen=True)
class ProvideRef:
    component_id: int
    provide: str

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "ProvideRef":
        raw = require_object(raw, "provide ref")
        return cls(
            component_id=require_int(raw, "component", "provide ref"),
            provide=require_str(raw, "name", "provide ref"),
        )


@dataclass(frozen=True)
class ResourceRef:
    component_id: int
    resource: str

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "ResourceRef":
        raw = require_object(raw, "resource ref")
        return cls(
            component_id=require_int(raw, "component", "resource ref"),
            resource=require_str(raw, "name", "resource ref"),
        )


@dataclass(frozen=True)
class FrameworkRef:
    authority_id: int
    capability: str

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "FrameworkRef":
        raw = require_object(raw, "framework ref")
        return cls(
            authority_id=require_int(raw, "authority", "framework ref"),
            capability=require_str(raw, "capability", "framework ref"),
        )


BindingSource = ProvideRef | ResourceRef | FrameworkRef


@dataclass(frozen=True)
class ScopeBinding:
    id: int
    source: BindingSource
    target: SlotRef
    capability: Capability


@dataclass(frozen=True)
class ScopeImport:
    id: int
    target: SlotRef
    capability: Capability


@dataclass(frozen=True)
class ScopeExport:
    id: int
    source: BindingSource
    capability: Capability


@dataclass(frozen=True)
class ScenarioScope:
    components: list[Component]
    bindings: list[ScopeBinding]
    imports: list[ScopeImport]
    exports: list[ScopeExport]

    def edges(self) -> Iterator[ScopeBinding | ScopeImport | ScopeExport]:
        yield from self.imports
        yield from self.bindings
        yield from self.exports

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "ScenarioScope":
        return cls(
            components=load_components(raw),
            bindings=load_bindings(raw),
            imports=load_imports(raw),
            exports=load_exports(raw),
        )


class AttachmentJson(TypedDict):
    target: int
    interposer_slot: str
    interposer_provide: str


class InterposerComponentJson(TypedDict, total=False):
    config: Any
    config_schema: Any
    program: dict[str, Any] | None
    slots: dict[str, Any]
    provides: dict[str, Any]
    resources: dict[str, Any]
    metadata: Any


class InterpositionJson(TypedDict):
    interposer: InterposerComponentJson
    attachments: list[AttachmentJson]


@dataclass(frozen=True)
class OverlayRequest:
    scope: ScenarioScope

    @classmethod
    def from_bytes(cls, raw: bytes) -> "OverlayRequest":
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise RequestParseError(f"invalid JSON request body: {err}") from err
        if not isinstance(payload, dict):
            raise RequestParseError("overlay request body must be a JSON object")
        raw_scope = payload.get("scope")
        if not isinstance(raw_scope, dict):
            raise RequestParseError("overlay request must contain an object `scope` field")
        return cls(scope=ScenarioScope.from_json(raw_scope))


def attachment(
    target: int, interposer_slot: str, interposer_provide: str
) -> AttachmentJson:
    return {
        "target": target,
        "interposer_slot": interposer_slot,
        "interposer_provide": interposer_provide,
    }


def interposition(
    interposer: InterposerComponentJson, attachments: list[AttachmentJson]
) -> InterpositionJson:
    return {
        "interposer": interposer,
        "attachments": attachments,
    }


def serve_overlay(
    port: int,
    build_interpositions: Callable[[OverlayRequest], Iterable[InterpositionJson]],
) -> None:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                request = OverlayRequest.from_bytes(raw)
                interpositions = list(build_interpositions(request))
                send_json(self, 200, {"interpositions": interpositions})
            except RequestParseError as err:
                send_json(self, 400, {"error": str(err)})
            except Exception as err:
                send_json(self, 500, {"error": str(err)})

        def log_message(self, fmt: str, *args: object) -> None:
            return

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", port), Handler) as httpd:
        httpd.serve_forever()


def load_components(scope: dict[str, Any]) -> list[Component]:
    raw_components = scope.get("components", [])
    if not isinstance(raw_components, list):
        raise RequestParseError("`scope.components` must be a list")
    components = []
    for raw_component in raw_components:
        if not isinstance(raw_component, dict):
            raise RequestParseError("`scope.components` entries must be objects")
        components.append(Component.from_json(raw_component))
    return components


def load_bindings(scope: dict[str, Any]) -> list[ScopeBinding]:
    raw_bindings = scope.get("bindings", [])
    if not isinstance(raw_bindings, list):
        raise RequestParseError("`scope.bindings` must be a list")
    bindings = []
    for raw_binding in raw_bindings:
        if not isinstance(raw_binding, dict):
            raise RequestParseError("`scope.bindings` entries must be objects")
        bindings.append(
            ScopeBinding(
                id=require_int(raw_binding, "id", "binding"),
                source=parse_binding_source(raw_binding.get("from")),
                target=SlotRef.from_json(raw_binding.get("to")),
                capability=Capability.from_json(raw_binding.get("capability", {})),
            )
        )
    return bindings


def load_imports(scope: dict[str, Any]) -> list[ScopeImport]:
    raw_imports = scope.get("imports", [])
    if not isinstance(raw_imports, list):
        raise RequestParseError("`scope.imports` must be a list")
    imports = []
    for raw_import in raw_imports:
        if not isinstance(raw_import, dict):
            raise RequestParseError("`scope.imports` entries must be objects")
        imports.append(
            ScopeImport(
                id=require_int(raw_import, "id", "import"),
                target=SlotRef.from_json(raw_import.get("to")),
                capability=Capability.from_json(raw_import.get("capability", {})),
            )
        )
    return imports


def load_exports(scope: dict[str, Any]) -> list[ScopeExport]:
    raw_exports = scope.get("exports", [])
    if not isinstance(raw_exports, list):
        raise RequestParseError("`scope.exports` must be a list")
    exports = []
    for raw_export in raw_exports:
        if not isinstance(raw_export, dict):
            raise RequestParseError("`scope.exports` entries must be objects")
        exports.append(
            ScopeExport(
                id=require_int(raw_export, "id", "export"),
                source=parse_binding_source(raw_export.get("from")),
                capability=Capability.from_json(raw_export.get("capability", {})),
            )
        )
    return exports


def parse_binding_source(raw: Any) -> BindingSource:
    raw = require_object(raw, "binding source")
    if "Component" in raw:
        return ProvideRef.from_json(raw["Component"])
    if "Resource" in raw:
        return ResourceRef.from_json(raw["Resource"])
    if "Framework" in raw:
        return FrameworkRef.from_json(raw["Framework"])
    raise RequestParseError("binding source must be Component, Resource, or Framework")


def send_json(
    handler: http.server.BaseHTTPRequestHandler, status: int, payload: dict[str, Any]
) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
