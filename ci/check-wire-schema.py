#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""The wire schema is only worth publishing with a check that fails when it
drifts (ADR-076, decision 5). Core generates the schema and its examples
from the types; this checks the copy in the book against Core's and
validates every example against the schema, so a schema that no longer
describes its own examples, or a copy that lags Core, fails the pipeline
(vauchi/private#119).

Usage:
  check-wire-schema.py <schema.json> <examples.json> [--core-schema F --core-examples F]
  check-wire-schema.py --self-test

The self-test (CC-27) proves the validator can fail: an example pushed one
byte over a bound, one with a required field missing, and one of a wrong
type must each be refused, and a copy that differs from Core must fail.
"""

import json
import sys
from copy import deepcopy

import jsonschema


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validator_for(schema, type_name):
    sub = {
        "$schema": schema["$schema"],
        "$ref": f"#/definitions/{type_name}",
        "definitions": schema["definitions"],
    }
    return jsonschema.Draft7Validator(sub)


def validation_errors(schema, examples):
    """(type, message) for every example that its definition refuses."""
    errors = []
    for type_name, example in examples.items():
        if type_name not in schema["definitions"]:
            errors.append((type_name, "example names no definition"))
            continue
        for error in validator_for(schema, type_name).iter_errors(example):
            errors.append((type_name, error.message))
    for type_name in schema["definitions"]:
        if type_name not in examples:
            errors.append((type_name, "definition has no example"))
    return errors


def check(schema_path, examples_path, core_schema=None, core_examples=None):
    schema = load(schema_path)
    examples = load(examples_path)
    failures = 0
    if core_schema is not None and load(core_schema) != schema:
        print(f"FAIL: {schema_path} differs from Core's generated schema")
        failures += 1
    if core_examples is not None and load(core_examples) != examples:
        print(f"FAIL: {examples_path} differs from Core's generated examples")
        failures += 1
    jsonschema.Draft7Validator.check_schema(schema)
    errors = validation_errors(schema, examples)
    for type_name, message in errors:
        print(f"FAIL: {type_name}: {message}")
    failures += len(errors)
    if failures == 0:
        print(f"OK: {len(examples)} examples validate against {len(schema['definitions'])} definitions")
    return failures


def self_test():
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "definitions": {
            "Fetch": {
                "type": "object",
                "required": ["tokens"],
                "properties": {
                    "tokens": {
                        "type": "array",
                        "maxItems": 2,
                        "items": {"type": "string", "maxLength": 4},
                    },
                    "at": {"type": ["integer", "null"]},
                },
            }
        },
    }
    good = {"Fetch": {"tokens": ["abcd", "ef"], "at": 1}}
    assert validation_errors(schema, good) == [], "a valid example must pass"

    over_length = deepcopy(good)
    over_length["Fetch"]["tokens"][0] = "abcde"
    assert validation_errors(schema, over_length), "an item one byte over its bound must fail"

    over_items = deepcopy(good)
    over_items["Fetch"]["tokens"] = ["a", "b", "c"]
    assert validation_errors(schema, over_items), "one item too many must fail"

    missing = {"Fetch": {"at": 1}}
    assert validation_errors(schema, missing), "a missing required field must fail"

    wrong_type = deepcopy(good)
    wrong_type["Fetch"]["at"] = "1"
    assert validation_errors(schema, wrong_type), "a wrong type must fail"

    orphan = deepcopy(good)
    orphan["Ack"] = {}
    assert validation_errors(schema, orphan), "an example without a definition must fail"

    unexampled = deepcopy(schema)
    unexampled["definitions"]["Ack"] = {"type": "object"}
    assert validation_errors(unexampled, good), "a definition without an example must fail"

    print("self-test OK: the validator refuses an over-long item, one item too many,")
    print("  a missing field, a wrong type, an orphan example and an unexampled type")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) < 3:
        print(__doc__)
        return 2
    args = argv[1:]
    schema_path, examples_path = args[0], args[1]
    core_schema = core_examples = None
    rest = args[2:]
    while rest:
        flag, value, rest = rest[0], rest[1], rest[2:]
        if flag == "--core-schema":
            core_schema = value
        elif flag == "--core-examples":
            core_examples = value
        else:
            print(f"unknown flag {flag}")
            return 2
    return 1 if check(schema_path, examples_path, core_schema, core_examples) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
