"""Versioned JSON Schema (draft 2020-12) of the Nunmathi JSON export, for SIEM/SOAR ingestion.

Compatibility policy: the minor version grows when fields are added (consumers must ignore unknown
fields, hence additionalProperties is left open); the major version grows when a field is removed,
renamed or changes type.
"""
from __future__ import annotations

from .analyzer import SCHEMA_VERSION

RISK = {"enum": ["High", "Medium", "Low", "Informational"]}
LETTER = {"enum": ["A+", "A", "B", "C", "D", "F"]}
CONF = {"enum": ["High", "Medium", "Low", "None", None]}
NUM_OR_NULL = {"type": ["number", "null"]}
INT_OR_NULL = {"type": ["integer", "null"]}
STR_OR_NULL = {"type": ["string", "null"]}

GRADE = {"type": "object", "required": ["score", "letter"],
         "properties": {"score": {"type": "integer", "minimum": 0, "maximum": 100}, "letter": LETTER,
                        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "counts": {"type": "object", "additionalProperties": {"type": "integer"}}}}

TECHNIQUE_REF = {"type": "object", "required": ["id", "name", "tactic"],
                 "properties": {"id": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"}, "name": {"type": "string"},
                                "tactic": {"type": "string", "pattern": r"^TA\d{4}$"}, "url": {"type": "string"}}}

ALERT = {"type": "object",
         "required": ["uid", "id", "name", "risk", "confidence", "description", "evidence", "solution", "tunnel"],
         "properties": {
             "uid": {"type": "integer", "description": "unique within one report"},
             "id": {"type": "string", "pattern": r"^NM-\d{3}$", "description": "rule identifier"},
             "name": {"type": "string"}, "risk": RISK,
             "confidence": {"enum": ["Confirmed", "Firm", "Tentative"]},
             "description": {"type": "string"}, "evidence": {"type": "string"}, "solution": {"type": "string"},
             "references": {"type": "array", "items": {"type": "string"}},
             "standards": {"type": "array", "items": {"type": "string"}},
             "attack": {"type": "array", "items": TECHNIQUE_REF},
             "params": {"type": "object"},
             "tunnel": {"type": "string", "description": "tunnel id, empty for capture-wide findings"}}}

PROOF_STEP = {"type": "object", "required": ["hypothesis", "verdict"],
              "properties": {"hypothesis": {"type": "string"}, "label": {"type": "string"},
                             "claim": {"type": "string"}, "reason": {"type": "string"},
                             "verdict": {"type": "string"}, "block": {"type": "integer"},
                             "iv": {"type": "integer"}, "icv": {"type": "integer"}}}

CHILD_SA = {"type": "object", "required": ["id", "spi_out", "spi_in", "packets", "bytes", "geometry"],
            "properties": {
                "id": {"type": "string"}, "spi_out": STR_OR_NULL, "spi_in": STR_OR_NULL,
                "first_ts": {"type": "number"}, "last_ts": {"type": "number"},
                "packets": {"type": "integer"}, "bytes": {"type": "integer"}, "udp_encap": {"type": "boolean"},
                "geometry": {"type": "object", "properties": {
                    "best": {"type": ["object", "null"]}, "confidence": CONF, "p_spurious": NUM_OR_NULL,
                    "distinct_lengths": {"type": "integer"},
                    "proof": {"type": "array", "items": PROOF_STEP},
                    "mode": {"type": ["object", "null"], "properties": {
                        "mode": {"enum": ["tunnel", "transport", "unknown"]}, "confidence": CONF}},
                    "length_hist": {"type": "object"}}}}}

TUNNEL = {"type": "object",
          "required": ["id", "initiator", "responder", "version", "ike_sas", "child_sas", "lifetimes", "pfs",
                       "posture", "grade"],
          "properties": {
              "id": {"type": "string"}, "initiator": {"type": "string"}, "responder": {"type": "string"},
              "peers": {"type": "array", "items": {"type": "string"}},
              "version": {"enum": [1, 2]}, "first_ts": {"type": "number"}, "last_ts": {"type": "number"},
              "ike_sas": {"type": "array", "items": {"type": "object", "properties": {
                  "ispi": {"type": "string"}, "rspi": {"type": "string"}, "ladder": {"type": "array"}}}},
              "child_sas": {"type": "array", "items": CHILD_SA},
              "rekey_events": {"type": "array"},
              "ike_crypto": {"type": ["object", "null"]},
              "lifetimes": {"type": "object", "properties": {
                  "child_rekey_interval": INT_OR_NULL, "ike_rekey_interval": INT_OR_NULL,
                  "child_lower_bound": INT_OR_NULL, "ike_lower_bound": INT_OR_NULL,
                  "observed_seconds": {"type": "integer"}}},
              "pfs": {"type": "object", "required": ["status"], "properties": {
                  "status": {"enum": ["enabled", "disabled", "unknown", "mixed"]}, "group": STR_OR_NULL,
                  "confidence": CONF}},
              "traffic": {"type": ["object", "null"], "properties": {
                  "segments": {"type": "array"},
                  "summary": {"type": "object", "properties": {
                      "windows": {"type": "integer"}, "mei_mean": NUM_OR_NULL, "mei_p90": NUM_OR_NULL,
                      "singleton_sets": NUM_OR_NULL, "ood_windows": {"type": "integer"},
                      "class_windows": {"type": "object"}}}}},
              "posture": {"type": "object"},
              "grade": GRADE,
              "recommended": {"type": "array", "items": {"type": "string"}},
              "alert_ids": {"type": "array", "items": {"type": "string"}},
              "esp_packets": {"type": "integer"}, "esp_bytes": {"type": "integer"}}}

ATTACK = {"type": "object", "required": ["tactics", "hit_techniques"],
          "properties": {"version": {"type": "string"},
                         "hit_techniques": {"type": "array", "items": {"type": "string"}},
                         "unmapped_rules": {"type": "array", "items": {"type": "string"}},
                         "tactics": {"type": "array", "items": {"type": "object", "properties": {
                             "id": {"type": "string"}, "name": {"type": "string"},
                             "techniques": {"type": "array", "items": {"type": "object", "properties": {
                                 "id": {"type": "string"}, "name": {"type": "string"},
                                 "alerts": {"type": "array"}, "max_risk": {"enum": RISK["enum"] + [None]}}}}}}}}}


def report_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://nunmathi.local/schema/report-{SCHEMA_VERSION}.json",
        "title": "Nunmathi analysis report",
        "description": "JSON export of one Nunmathi analysis (GET /api/analyses/{id}/report.json). "
                       "Consumers must ignore unknown fields.",
        "type": "object",
        "required": ["nunmathi_report", "schema_version", "engine", "analysis", "file", "grade", "tunnels",
                     "alerts", "attack"],
        "properties": {
            "nunmathi_report": {"const": 1},
            "schema_version": {"type": "string", "pattern": r"^1\.\d+\.\d+$"},
            "engine": {"type": "string"},
            "analysis": {"type": "object", "required": ["id", "name", "source", "created"], "properties": {
                "id": {"type": "string"}, "name": {"type": "string"},
                "source": {"enum": ["upload", "demo", "live", "testbed", "cli"]},
                "created": {"type": "number"}, "sha256": STR_OR_NULL, "size": INT_OR_NULL}},
            "file": {"type": "object", "required": ["frames"], "properties": {
                "frames": {"type": "integer"}, "ike": {"type": "integer"}, "esp": {"type": "integer"},
                "first_ts": NUM_OR_NULL, "last_ts": NUM_OR_NULL, "bytes": {"type": "integer"}}},
            "grade": GRADE,
            "tunnels": {"type": "array", "items": TUNNEL},
            "alerts": {"type": "array", "items": ALERT},
            "attack": ATTACK,
            "half_open": {"type": "array"},
            "audit": {"type": "array", "items": {"type": "object", "required": ["t", "stage"], "properties": {
                "t": {"type": "string"}, "elapsed": {"type": "number"}, "stage": {"type": "string"},
                "detail": {"type": "string"}}}},
            "model_card": {"type": "object"},
        },
    }
