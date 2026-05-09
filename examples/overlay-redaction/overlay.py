#!/usr/bin/env python3

import os

from overlay_lib import InterpositionJson, OverlayRequest, serve_overlay
from redactor_interposer import build_redaction_interposition, parse_redaction_terms

PORT = int(os.environ["PORT"])
REDACTION_TERMS = parse_redaction_terms(os.environ["REDACTION_TERMS"])


def build_interpositions(request: OverlayRequest) -> list[InterpositionJson]:
    return [
        build_redaction_interposition(edge.id, REDACTION_TERMS)
        for edge in request.scope.edges()
        if edge.capability.kind == "a2a"
    ]

serve_overlay(PORT, build_interpositions)
