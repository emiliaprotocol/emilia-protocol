# SPDX-License-Identifier: Apache-2.0
"""The native lane of the CAID conformance corpora, built as Python values.

The encoding is described in native.mjs beside this file. The conformance
runner (run.py) and the fuzz driver (caid/fuzz/drivers/py_driver.py) both
build host values here, so the two can never disagree about a tag. An
unknown tag is an error in the corpus, never a value.
"""

import math


def units_to_str(units):
    """A str of these UTF-16 code units: a well-formed pair is one code
    point, and a lone surrogate stays a lone surrogate."""
    out = []
    i = 0
    while i < len(units):
        u = units[i]
        if 0xD800 <= u <= 0xDBFF and i + 1 < len(units) and 0xDC00 <= units[i + 1] <= 0xDFFF:
            out.append(chr(0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)))
            i += 2
            continue
        out.append(chr(u))
        i += 1
    return "".join(out)


def tag_of(v):
    if isinstance(v, dict) and len(v) == 1:
        (k,) = v.keys()
        if isinstance(k, str) and k.startswith("$"):
            return k
    return None


_HOSTS = {
    "nan": lambda enclosing: math.nan,
    "infinity": lambda enclosing: math.inf,
    "-infinity": lambda enclosing: -math.inf,
    "negative_zero": lambda enclosing: -0.0,
    "cyclic": lambda enclosing: enclosing,
    "opaque": lambda enclosing: set(),
}


def build_native(encoded, enclosing=None):
    """The Python host value of a native-lane encoding."""
    tag = tag_of(encoded)
    if tag == "$units":
        return units_to_str(encoded["$units"])
    if tag == "$object":
        out = {}
        for k, x in encoded["$object"]:
            key = k if isinstance(k, str) else build_native(k, enclosing)
            out[key] = build_native(x, out)
        return out
    if tag == "$repeat":
        spec = encoded["$repeat"]
        return spec["unit"] * int(spec["count"])
    if tag == "$nest":
        spec = encoded["$nest"]
        value = build_native(spec["leaf"], enclosing)
        for _ in range(int(spec["depth"])):
            value = {"a": value} if spec["container"] == "object" else [value]
        return value
    if tag == "$dag":
        spec = encoded["$dag"]
        value = build_native(spec["leaf"], enclosing)
        for _ in range(int(spec["depth"])):
            value = [value, value]
        return value
    if tag == "$host":
        host = _HOSTS.get(encoded["$host"])
        if host is None:
            raise ValueError("unknown $host " + str(encoded["$host"]))
        return host(enclosing)
    if isinstance(encoded, list):
        out = []
        for x in encoded:
            out.append(build_native(x, out))
        return out
    if isinstance(encoded, dict):
        out = {}
        for k, x in encoded.items():
            out[k] = build_native(x, out)
        return out
    return encoded
