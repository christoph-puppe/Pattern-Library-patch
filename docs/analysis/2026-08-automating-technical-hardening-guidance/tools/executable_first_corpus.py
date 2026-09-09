#!/usr/bin/env python3
"""
executable_first_corpus.py: write the executable-first corpus into examples/executable-first/oscal/.

WHAT THIS IS. The other three approaches are described from OSCAL their
proponents published. The fourth exists as a concept note and no proponent has
published OSCAL for it, so the site generates the corpus itself, from two
pieces of hardening guidance this repository already holds, in the shape the
note proposes. Every control, part, identifier, value and script body below is
taken from a published file; the generator chose the shape and nothing else.

Two routes, because the note names two.

  The catalog route, where the author of the requirement is the author of the
  check. The CIS Ubuntu Linux 24.04 LTS Benchmark publishes, for every
  recommendation, an audit procedure that is often a complete bash script, and
  a check expression naming the Script Check Engine script CIS-CAT runs with the
  value it exports to it. Each recommendation becomes a control carrying an
  assessment-objective part, an assessment-method part with method TEST and the
  audit procedure as its body, the note's props, a link to the objective, a link
  to a back-matter resource for each SCE script named, and a parameter carrying
  the exported value. CIS's own four profiles become four OSCAL profiles, and
  CIS's own references to NIST SP 800-53 become a mapping collection.

  The profile route, where someone other than the catalog author supplies the
  check. The Canonical Ubuntu 24.04 LTS STIG maps every rule to SP 800-53
  controls through its CCIs, so it becomes a profile that imports the NIST
  Revision 5 catalog and adds, to each control a rule serves, an
  assessment-objective part carrying the rule and an assessment-method part
  carrying DISA's check text. The STIG publishes that check as text, so the
  method carries no language or evaluation prop, and that absence is the
  finding rather than a gap in the generator.

WHAT IS NOT HERE. The SCE script bodies ship with CIS-CAT and are not in the
benchmark file, so their resources carry a name and no hash. DISA's automated
checks ship as SCAP content that is not held, so the STIG methods have prose
bodies only. Neither is filled in.

Deterministic: uuids are derived from identifiers, and the one date the
generator owns is a constant that moves only when the shape changes. Run with
--check to fail if the committed files are stale, and with --validate to run an
OSCAL validator over every file if one is on the path.
"""

from __future__ import annotations

import collections
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
SITE_ROOT = os.path.dirname(TOOLS_DIR)
OUT_DIR = os.path.join(SITE_ROOT, "examples", "executable-first", "oscal")

CIS_JSON = os.path.join(SITE_ROOT, "sources", "cis",
                        "CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.json")
CIS_PDF = os.path.join(SITE_ROOT, "sources", "cis",
                       "CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf")
STIG_XML = os.path.join(SITE_ROOT, "sources", "disa",
                        "U_CAN_Ubuntu_24-04_LTS_STIG_V1R5_Manual-xccdf.xml")
#  The published conversion of the same STIG, held as part of the assessment-first
#  corpus. It is the source of the CCI to control mapping, which it derived from
#  DISA's CCI list, and nothing else is taken from it.
STIG_MAPPING = os.path.join(SITE_ROOT, "examples", "assessment-first", "DISA",
                            "STIG_XCCDF to OSCAL Assessment Plans", "ubuntu24.json")

NIST_CATALOG_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")

#  The concept note's namespace, carried as the note wrote it. The note calls it
#  a placeholder; the vocabulary is the point, and it is not the site's.
AUTO_NS = "https://example.org/ns/oscal-automation"
#  The namespace the published STIG conversion uses for the STIG's own
#  identifiers, reused so the same identifier carries the same namespace in
#  both corpora.
STIG_NS = "https://public.cyber.mil/stigs/ns"

OSCAL_VERSION = "1.2.1"
#  The one date the generator owns. It moves when the shape changes, not when
#  the generator is run, so a regenerated file is byte-identical.
GENERATED = "2026-09-09T00:00:00Z"

FILES = {
    "catalog": "cis-ubuntu-24-04-lts-benchmark-catalog.json",
    "mapping": "cis-ubuntu-24-04-lts-to-nist-sp-800-53-rev5-mapping.json",
    "stig": "nist-sp-800-53-rev5-with-ubuntu-24-04-lts-stig-profile.json",
    "rules": "cis-ubuntu-24-04-lts-benchmark-automation-scripts-component-definition.json",
}
#  The one file written in the Rules shape rather than the assessment-method
#  shape: a validation component carrying an automation-scripts assembly, which
#  OSCAL 1.2.1 does not define. It is expected to fail validation, and the
#  harness checks that it does, because a proposed assembly that validated
#  would mean the validator was not looking.
EXPECT_INVALID = {FILES["rules"]}
CIS_CONTROLS_NS = "https://cisecurity.org/ns/oscal"
CIS_PROFILE_FILES = {
    "Level 1 - Server": "cis-ubuntu-24-04-lts-level-1-server-profile.json",
    "Level 2 - Server": "cis-ubuntu-24-04-lts-level-2-server-profile.json",
    "Level 1 - Workstation": "cis-ubuntu-24-04-lts-level-1-workstation-profile.json",
    "Level 2 - Workstation": "cis-ubuntu-24-04-lts-level-2-workstation-profile.json",
}


def uid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "tfg-executable-first:" + seed))


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def rel_from_out(path: str) -> str:
    return os.path.relpath(path, OUT_DIR).replace(os.sep, "/")


# --------------------------------------------------------------------------- #
# CIS markup to Markdown                                                       #
# --------------------------------------------------------------------------- #
#  The benchmark's prose is XHTML in strings, and its scripts sit in code
#  blocks whose newlines are entity-escaped <br /> markers. OSCAL prose is
#  Markdown, so the blocks become fenced code and the rest becomes paragraphs,
#  lists, emphasis and inline code. Nothing is reworded.

CODE_BLOCK = re.compile(r'<xhtml:code class="code_block">(.*?)</xhtml:code>', re.S)


def code_text(raw: str) -> str:
    text = html.unescape(raw).replace("<br />", "\n")
    return text.strip("\n")


def is_bash(code: str) -> bool:
    return code.lstrip().startswith(("#!/usr/bin/env bash", "#!/bin/bash"))


def to_markdown(s: str) -> str:
    blocks: list[str] = []

    def stash(m):
        code = code_text(m.group(1))
        lang = "bash" if is_bash(code) else ""
        blocks.append(f"\n\n```{lang}\n{code}\n```\n\n")
        return f"\x00{len(blocks) - 1}\x00"

    s = CODE_BLOCK.sub(stash, s)
    s = re.sub(r"<xhtml:(?:br|hr)\s*/?>", "\n", s)
    s = re.sub(r"<xhtml:li>", "- ", s)
    s = re.sub(r"</xhtml:li>", "\n", s)
    s = re.sub(r"</xhtml:p>", "\n\n", s)
    s = re.sub(r"<xhtml:strong>(.*?)</xhtml:strong>", r"**\1**", s, flags=re.S)
    s = re.sub(r"<xhtml:em>(.*?)</xhtml:em>", r"*\1*", s, flags=re.S)
    s = re.sub(r"<xhtml:(?:code|span)[^>]*>(.*?)</xhtml:(?:code|span)>",
               r"`\1`", s, flags=re.S)
    s = re.sub(r'<xhtml:a[^>]*href="([^"]+)"[^>]*>(.*?)</xhtml:a>',
               r"[\2](\1)", s, flags=re.S)
    s = re.sub(r"</?xhtml:[a-z0-9]+[^>]*>", "", s)
    s = html.unescape(s)
    s = re.sub(r"\x00(\d+)\x00", lambda m: blocks[int(m.group(1))], s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


# --------------------------------------------------------------------------- #
# CIS: the benchmark as a catalog with executable assessment methods           #
# --------------------------------------------------------------------------- #

def cis_rules(group_node):
    """Every rule under a group, in document order."""
    g = group_node["Group"]
    for r in g.get("Rules", []):
        yield r["Rule"]
    for sub in g.get("Groups", []):
        yield from cis_rules(sub)


def sce_artifacts(checks) -> list[dict]:
    """The Script Check Engine artifacts in a rule's check expression."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            a = o.get("artifact")
            if isinstance(a, dict) and a.get("type") == "sce_check_v1":
                ps = {p["parameter"]["name"]: p["parameter"]["value"]
                      for p in a.get("parameters", [])}
                out.append(ps)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(checks)
    return out


def cis_number(rid: str) -> str:
    m = re.search(r"_rule_(\d+(?:\.\d+)*)_", rid)
    return m.group(1) if m else ""


def nist_refs(rule) -> list[str]:
    """The SP 800-53 controls a CIS rule names in its own identifiers."""
    #  The benchmark writes the list four ways: comma and space, comma alone,
    #  a full stop, and a bare space. The control tokens are read by their
    #  shape rather than by splitting, and anything else in the string is
    #  refused rather than skipped.
    out = []
    for ident in rule.get("idents", []):
        v = ident.get("systemValue", "")
        if not v.startswith("NIST SP 800-53 Rev. 5:"):
            continue
        body = v.split(":", 1)[1]
        rest = re.sub(r"[A-Z]{2}-\d+(?:\(\d+\))?", "", body)
        if re.sub(r"[\s,.]", "", rest):
            raise SystemExit(f"{rule['id']}: cannot read control list {body!r}")
        for m in re.finditer(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", body):
            cid = f"{m.group(1).lower()}-{m.group(2)}"
            if m.group(3):
                cid += "." + m.group(3)
            if cid not in out:
                out.append(cid)
    return out


def cis_control(rule, platform: str, scripts: dict) -> dict:
    rid = rule["id"]
    num = cis_number(rid)
    automated = rule.get("assessmentstatus") == "automated"
    audit = to_markdown(rule.get("auditcheck", ""))
    codes = [code_text(c) for c in CODE_BLOCK.findall(rule.get("auditcheck", ""))]
    sce = sce_artifacts(rule.get("checks"))

    method = {
        "id": rid + "_asm",
        "name": "assessment-method",
        "props": [
            {"name": "method", "value": "TEST" if automated else "EXAMINE"},
            {"name": "platform", "value": platform, "ns": AUTO_NS},
        ],
        "links": [{"rel": "assessment-objective", "href": "#" + rid + "_obj"}],
    }
    #  Which engine runs the body. Bash where the audit procedure is a bash
    #  script or an SCE script is named; nothing otherwise, because the body is
    #  then a procedure a person follows and no engine is named for it.
    if any(is_bash(c) for c in codes) or sce:
        method["props"].append({"name": "language", "value": "bash", "ns": AUTO_NS})
    #  How the result is judged. CIS's audit scripts print an audit result line
    #  reading ** PASS ** or ** FAIL **, so where the body carries one the
    #  evaluation is a regex over standard output, which is in the note's own
    #  enumeration. Nothing is asserted about scripts that print no such line.
    if any("** PASS **" in c for c in codes):
        method["props"].append({"name": "evaluation", "value": "stdout-regex",
                                "ns": AUTO_NS})
        method["props"].append({"name": "pass-condition",
                                "value": r"\*\* PASS \*\*", "ns": AUTO_NS})
    #  One link per distinct SCE script the check expression names. The script
    #  is the body the note says can live in back-matter; the benchmark file
    #  names it and does not carry it.
    for name in sorted({a.get("script") for a in sce if a.get("script")}):
        if name not in scripts:
            scripts[name] = {"uuid": uid("script:" + name), "used_by": 0}
        scripts[name]["used_by"] += 1
        method["links"].append({"rel": "script", "href": "#" + scripts[name]["uuid"]})
    if audit:
        method["prose"] = audit

    parts = [
        {"id": rid + "_smt", "name": "statement",
         "prose": to_markdown(rule.get("description", ""))},
    ]
    if rule.get("rationale"):
        parts.append({"id": rid + "_rationale", "name": "rationale",
                      "prose": to_markdown(rule["rationale"])})
    parts.append({"id": rid + "_obj", "name": "assessment-objective",
                  "prose": rule["title"]})
    parts.append(method)
    if rule.get("fixtext"):
        #  A different part with a different name, as the note asks, so that a
        #  check and a fix are never one thing an executor runs by mistake.
        parts.append({"id": rid + "_rem", "name": "remediation", "ns": AUTO_NS,
                      "prose": to_markdown(rule["fixtext"])})

    ctl = {"id": rid, "title": f"{num} {rule['title']}".strip()}
    #  The value CIS-CAT exports to the script, as a parameter of the control,
    #  which is the note's route for tailoring: one script, many controls,
    #  each with its own value. Only where the rule exports exactly one, so
    #  that a parameter never stands for two different values. Parameter ids
    #  are unique across a catalog, so the id cannot be the variable's name;
    #  the class carries that, and what an executor should do with it is an
    #  open question the site records.
    exports = [a for a in sce if a.get("export_variable_name") == "XCCDF_VALUE_REGEX"
               and a.get("export_variable_value")]
    if len(exports) == 1:
        ctl["params"] = [{
            "id": rid + "_xccdf-value-regex",
            "class": "XCCDF_VALUE_REGEX",
            "label": f"Value exported to {exports[0].get('script')} as XCCDF_VALUE_REGEX",
            "values": [exports[0]["export_variable_value"]],
        }]
    refs = []
    for ident in rule.get("idents", []):
        href = ident.get("cc8:controlURI")
        if href:
            refs.append({"rel": "reference", "href": href})
    if refs:
        ctl["links"] = refs
    ctl["parts"] = parts
    return ctl


#  OSCAL's group holds either groups or controls and never both, which the
#  published JSON schema enforces and XCCDF does not. One benchmark section,
#  6.1.2, holds three recommendations and a sub-section, so its own
#  recommendations go into a sub-group named after the section. That is the
#  one place the catalog's structure is not the benchmark's, and the group's
#  id says so.
MIXED_SUFFIX = "_recommendations"


def cis_group(node, platform, scripts) -> dict:
    g = node["Group"]
    out = {"id": g["id"], "title": g["title"]}
    subs = [cis_group(s, platform, scripts) for s in g.get("Groups", [])]
    ctls = [cis_control(r["Rule"], platform, scripts) for r in g.get("Rules", [])]
    if subs and ctls:
        subs.insert(0, {"id": g["id"] + MIXED_SUFFIX,
                        "title": g["title"] + " (the section's own recommendations)",
                        "controls": ctls})
        ctls = []
    if subs:
        out["groups"] = subs
    if ctls:
        out["controls"] = ctls
    return out


def build_cis(bench) -> tuple[dict, dict, list]:
    platform = bench["platforms"][0]
    scripts: dict = {}
    groups = [cis_group(gl, platform, scripts) for gl in bench["Guidelines"]]
    accepted = [s["accepted"] for s in bench.get("status", []) if "accepted" in s][0]
    resources = [
        {"uuid": uid("source:cis-json"),
         "title": bench["title"] + " (CIS-CAT benchmark file)",
         "description": ("The benchmark file every control, part and value in "
                         "this catalog was taken from. Held on the basis the "
                         "repository's source inventory records."),
         "rlinks": [{"href": rel_from_out(CIS_JSON), "media-type": "application/json",
                     "hashes": [{"algorithm": "SHA-256", "value": sha256(CIS_JSON)}]}]},
        {"uuid": uid("source:cis-pdf"),
         "title": bench["title"] + " (published document)",
         "rlinks": [{"href": rel_from_out(CIS_PDF), "media-type": "application/pdf",
                     "hashes": [{"algorithm": "SHA-256", "value": sha256(CIS_PDF)}]}]},
    ]
    for name in sorted(scripts):
        n = scripts[name]["used_by"]
        resources.append({
            "uuid": scripts[name]["uuid"],
            "title": name,
            "description": (f"Script Check Engine script, named by the check "
                            f"expression of {n} recommendation{'s' if n != 1 else ''}. "
                            f"It ships with CIS-CAT and is not held here, so this "
                            f"resource carries its name and no hash."),
            "rlinks": [{"href": name, "media-type": "application/x-sh"}],
        })
    catalog = {"catalog": {
        "uuid": uid("catalog:" + bench["id"]),
        "metadata": {
            "title": f"{bench['title']} v{bench['version']}, as a catalog with "
                     f"executable assessment methods",
            "published": accepted + "T00:00:00Z",
            "last-modified": GENERATED,
            "version": bench["version"],
            "oscal-version": OSCAL_VERSION,
            "links": [{"rel": "source", "href": "#" + uid("source:cis-json")},
                      {"rel": "source", "href": "#" + uid("source:cis-pdf")}],
            "remarks": ("Generated by tools/executable_first_corpus.py from the "
                        "benchmark file named in back-matter. Every control, part, "
                        "identifier, value and script body is taken from that "
                        "file. The shape, an assessment objective and an "
                        "executable assessment method on every control, is the "
                        "one the concept note on executable assessment methods "
                        "proposes, and the generator chose it, not CIS. One "
                        "section of the benchmark holds recommendations and a "
                        "sub-section together, which an OSCAL group cannot, so "
                        "its own recommendations sit in a sub-group named after "
                        "it."),
        },
        "groups": groups,
        "back-matter": {"resources": resources},
    }}
    return catalog, scripts, list(cis_rules_all(bench))


def cis_rules_all(bench):
    for gl in bench["Guidelines"]:
        yield from cis_rules(gl)


# --------------------------------------------------------------------------- #
# The Rules shape: the same benchmark as a validation component               #
# --------------------------------------------------------------------------- #
#  The second construct the site compares. A typed assembly, automation-scripts,
#  on the implemented requirements of a validation component: one script
#  object per audit or remediation script, with its language, the benchmark
#  profiles it applies to, how its output is judged, and the script as
#  payload. The shape is the site's own encoding of the Rules construct
#  carrying code. The requirements are keyed to CIS Controls v8 through the
#  references the benchmark carries in its own identifiers; the
#  recommendations that name no CIS Control sit under a second control
#  implementation whose source is the catalog beside this file, so nothing is
#  dropped.

CC8_URI = re.compile(r"/v8\.\d+/control/(\d+)/subcontrol/(\d+)$")


def cc8_ids(rule) -> list[str]:
    """CIS Controls v8 safeguard ids a rule names, as cisc-CCC.SSS."""
    out = []
    for ident in rule.get("idents", []):
        m = CC8_URI.search(ident.get("cc8:controlURI", ""))
        if m:
            cid = f"cisc-{int(m.group(1)):03d}.{int(m.group(2)):03d}"
            if cid not in out:
                out.append(cid)
    return out


def rule_profiles(bench) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in bench["Profiles"]:
        for sel in p["selects"]:
            if sel["select"]["selected"] == "true":
                out.setdefault(sel["select"]["idref"], []).append(p["title"])
    return out


def automation_scripts(rule, profiles: list[str], under: str) -> list[dict]:
    #  A script object sits under one requirement, and a recommendation that
    #  names two CIS Controls is carried under both, so the object is repeated
    #  and the uuid says which copy it is. The shape has no link between two
    #  requirements' scripts, which is one of the differences the site records.
    num = cis_number(rule["id"])
    out = []
    for kind, field in (("audit", "auditcheck"), ("remediation", "fixtext")):
        codes = [code_text(c) for c in CODE_BLOCK.findall(rule.get(field, ""))]
        for i, code in enumerate(c for c in codes if is_bash(c)):
            item = {
                "uuid": uid(f"script:{under}:{rule['id']}:{kind}:{i}"),
                "benchmark-rule-id": num,
                "script-type": kind,
                "language": "bash",
                "applicable-profiles": profiles,
            }
            if kind == "audit" and "** PASS **" in code:
                item["evaluation-criteria"] = {
                    "method": "stdout-regex",
                    "pass-condition": r"^\*\* PASS \*\*$",
                    "fail-condition": r"^\*\* FAIL \*\*$",
                }
            item["payload"] = code + "\n"
            out.append(item)
    return out


def build_rules_cdef(bench, rules, catalog_file: str) -> dict:
    profiles = rule_profiles(bench)
    by_cc8: dict[str, list] = {}
    unmapped = []
    for r in rules:
        ids = cc8_ids(r)
        if ids:
            for cid in ids:
                by_cc8.setdefault(cid, []).append(r)
        else:
            unmapped.append(r)

    def requirement(cid: str, members: list, title: str) -> dict:
        req = {
            "uuid": uid("req:" + cid),
            "control-id": cid,
            "description": title,
            "automation-scripts": [],
        }
        rationale = [f"{cis_number(r['id'])}: " + to_markdown(r["rationale"])
                     for r in members if r.get("rationale")]
        if rationale:
            req["props"] = [{"name": "rationale", "value": "\n\n".join(rationale),
                             "ns": CIS_CONTROLS_NS}]
        for r in members:
            req["automation-scripts"].extend(
                automation_scripts(r, profiles.get(r["id"], []), cid))
        if not req["automation-scripts"]:
            del req["automation-scripts"]
        return req

    mapped_reqs = []
    for cid in sorted(by_cc8):
        members = by_cc8[cid]
        title = "; ".join(f"{cis_number(r['id'])} {r['title']}" for r in members)
        mapped_reqs.append(requirement(cid, members, title))
    unmapped_reqs = [requirement(r["id"], [r], f"{cis_number(r['id'])} {r['title']}")
                     for r in unmapped]
    accepted = [s["accepted"] for s in bench.get("status", []) if "accepted" in s][0]
    return {"component-definition": {
        "uuid": uid("cdef:" + bench["id"]),
        "metadata": {
            "title": f"{bench['title']} v{bench['version']}, as a validation component "
                     f"carrying automation scripts",
            "published": accepted + "T00:00:00Z",
            "last-modified": GENERATED,
            "version": bench["version"],
            "oscal-version": OSCAL_VERSION,
            "remarks": ("Generated by tools/executable_first_corpus.py from the same "
                        "benchmark file as the catalog beside it, in the Rules shape: "
                        "an automation-scripts assembly on the implemented requirements "
                        "of a validation component, the site's own encoding of that "
                        "construct. OSCAL 1.2.1 does not define that assembly, so this "
                        "file does not validate, and it is not meant to. Every script, "
                        "identifier, profile and rationale is taken from the benchmark "
                        "file; the requirements are keyed to CIS Controls v8 through the "
                        "references in the benchmark's own identifiers, and the "
                        "recommendations that name none sit under a second control "
                        "implementation whose source is the catalog beside this file."),
        },
        "components": [{
            "uuid": uid("component:" + bench["id"]),
            "type": "validation",
            "title": f"{bench['title']} bash automation",
            "description": ("The audit and remediation scripts the benchmark publishes, "
                            "one script object each, on the CIS Control each "
                            "recommendation names."),
            "props": [{"name": "platform", "value": bench["platforms"][0],
                       "ns": AUTO_NS}],
            "control-implementations": [
                {
                    "uuid": uid("impl:cc8:" + bench["id"]),
                    "source": "http://cisecurity.org/20-cc/v8.0/",
                    "description": ("Scripts keyed to the CIS Controls v8 safeguards the "
                                    "benchmark's recommendations reference."),
                    "implemented-requirements": mapped_reqs,
                },
                {
                    "uuid": uid("impl:catalog:" + bench["id"]),
                    "source": catalog_file,
                    "description": ("Recommendations that reference no CIS Control, keyed "
                                    "to the catalog beside this file, one requirement per "
                                    "recommendation."),
                    "implemented-requirements": unmapped_reqs,
                },
            ],
        }],
    }}


def build_cis_profiles(bench, catalog_file: str) -> dict[str, dict]:
    out = {}
    for p in bench["Profiles"]:
        ids = [s["select"]["idref"] for s in p["selects"] if s["select"]["selected"] == "true"]
        out[CIS_PROFILE_FILES[p["title"]]] = {"profile": {
            "uuid": uid("profile:" + p["id"]),
            "metadata": {
                "title": f"{bench['title']} v{bench['version']}, {p['title']}",
                "published": GENERATED,
                "last-modified": GENERATED,
                "version": bench["version"],
                "oscal-version": OSCAL_VERSION,
                "remarks": ("The benchmark's own profile of that name, as the "
                            "selection of controls it makes. " + to_markdown(p["description"])),
            },
            "imports": [{"href": catalog_file,
                         "include-controls": [{"with-ids": ids}]}],
            "merge": {"as-is": True},
        }}
    return out


def build_mapping(bench, rules, catalog_file: str) -> dict:
    maps = []
    for r in rules:
        targets = nist_refs(r)
        if not targets:
            continue
        maps.append({
            "uuid": uid("map:" + r["id"]),
            "relationship": "subset-of",
            "sources": [{"type": "control", "id-ref": r["id"]}],
            "targets": [{"type": "control", "id-ref": c} for c in targets],
        })
    return {"mapping-collection": {
        "uuid": uid("mapping:" + bench["id"]),
        "metadata": {
            "title": f"{bench['title']} v{bench['version']} mapped to NIST SP 800-53 "
                     f"Revision 5",
            "published": GENERATED,
            "last-modified": GENERATED,
            "version": bench["version"],
            "oscal-version": OSCAL_VERSION,
            "remarks": ("Generated by tools/executable_first_corpus.py from the SP 800-53 "
                        "references the benchmark carries in its own identifiers. The "
                        "references are CIS's; the mapping model around them is the "
                        "generator's."),
        },
        "provenance": {
            "method": "hybrid",
            "matching-rationale": "semantic",
            "status": "draft",
            "mapping-description": (
                "Each map carries the SP 800-53 Revision 5 controls the "
                "benchmark names in the recommendation's own identifiers. CIS "
                "made the mapping; the generator transcribed it into the mapping "
                "model, which is why the method is hybrid. Every recommendation is "
                "narrower than the control it names, so every map is a subset "
                "relationship."),
        },
        "mappings": [{
            "uuid": uid("mapping-set:" + bench["id"]),
            "source-resource": {"type": "catalog", "href": catalog_file},
            "target-resource": {"type": "catalog", "href": NIST_CATALOG_URL},
            "maps": maps,
        }],
    }}


# --------------------------------------------------------------------------- #
# DISA: the STIG as a profile on NIST SP 800-53, one objective per rule        #
# --------------------------------------------------------------------------- #

def stig_rules():
    root = ET.parse(STIG_XML).getroot()
    ns = {"x": root.tag.split("}")[0].strip("{")}
    title = root.findtext("x:title", namespaces=ns)
    status = root.find("x:status", ns)
    release = root.findtext("x:plain-text[@id='release-info']", namespaces=ns) or ""
    rules = []
    for g in root.findall("x:Group", ns):
        r = g.find("x:Rule", ns)
        desc = r.findtext("x:description", namespaces=ns) or ""
        m = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", desc, re.S)
        rules.append({
            "group": g.get("id"),
            "rule": r.get("id"),
            "severity": r.get("severity"),
            "stig_id": r.findtext("x:version", namespaces=ns),
            "title": (r.findtext("x:title", namespaces=ns) or "").strip(),
            "discussion": (m.group(1) if m else desc).strip(),
            "ccis": [i.text for i in r.findall("x:ident", ns)],
            "check": (r.findtext("x:check/x:check-content", namespaces=ns) or "").strip(),
            "fix": (r.findtext("x:fixtext", namespaces=ns) or "").strip(),
        })
    return title, status.get("date"), status.text, release, rules


def stig_controls_by_group() -> dict[str, list[str]]:
    ap = json.load(open(STIG_MAPPING, encoding="utf-8"))["assessment-plan"]
    out = {}
    for a in ap["local-definitions"]["activities"]:
        props = a.get("props", [])
        gid = [p["value"] for p in props if p["name"] == "stig-group-id"][0]
        out[gid] = [p["value"] for p in props if p["name"] == "nist-control"]
    return out


def build_stig(platform: str) -> dict:
    title, date, status, release, rules = stig_rules()
    mapping = stig_controls_by_group()
    version = re.search(r"V\d+R\d+", os.path.basename(STIG_XML)).group(0)

    by_control: dict[str, dict] = collections.OrderedDict()
    for r in rules:
        controls = mapping[r["group"]]
        if not controls:
            raise SystemExit(f"{r['group']}: no control mapped")
        primary, others = controls[0], controls[1:]
        stem = r["stig_id"].lower()
        obj_id = f"{primary}_obj-{stem}"
        objective = {
            "id": obj_id,
            "name": "assessment-objective",
            "props": [
                {"name": "stig-group-id", "value": r["group"], "ns": STIG_NS},
                {"name": "stig-rule-id", "value": r["rule"], "ns": STIG_NS},
                {"name": "stig-id", "value": r["stig_id"], "ns": STIG_NS},
                {"name": "severity", "value": r["severity"], "ns": STIG_NS},
            ] + [{"name": "cci", "value": c, "ns": STIG_NS} for c in r["ccis"]],
            "prose": r["title"],
        }
        if r["discussion"]:
            objective["parts"] = [{"id": f"{primary}_dsc-{stem}", "name": "guidance",
                                   "prose": r["discussion"]}]
        #  Method TEST with a prose body and no language or evaluation prop.
        #  DISA publishes this check as text a person follows; the SCAP content
        #  that automates it ships separately and is not held.
        method = {
            "id": f"{primary}_asm-{stem}",
            "name": "assessment-method",
            "props": [
                {"name": "method", "value": "TEST"},
                {"name": "platform", "value": platform, "ns": AUTO_NS},
            ],
            "links": [{"rel": "assessment-objective", "href": "#" + obj_id}],
            "prose": r["check"],
        }
        parts = [objective, method]
        if r["fix"]:
            parts.append({"id": f"{primary}_rem-{stem}", "name": "remediation",
                          "ns": AUTO_NS, "prose": r["fix"]})
        by_control.setdefault(primary, {"parts": [], "links": []})["parts"] += parts
        #  A rule that serves more than one control puts its parts on the first
        #  and links the others to the objective, so one objective is targeted
        #  by one finding and every control it serves can reach it.
        for c in others:
            by_control.setdefault(c, {"parts": [], "links": []})["links"].append(
                {"rel": "assessment-objective", "href": "#" + obj_id})

    alters = []
    for cid in sorted(by_control):
        add = {"position": "ending"}
        if by_control[cid]["links"]:
            add["links"] = by_control[cid]["links"]
        if by_control[cid]["parts"]:
            add["parts"] = by_control[cid]["parts"]
        alters.append({"control-id": cid, "adds": [add]})

    return {"profile": {
        "uuid": uid("profile:stig:" + version),
        "metadata": {
            "title": f"NIST SP 800-53 Revision 5, with the {title} {version} as "
                     f"executable assessment methods",
            "published": date + "T00:00:00Z",
            "last-modified": GENERATED,
            "version": version,
            "oscal-version": OSCAL_VERSION,
            "links": [{"rel": "source", "href": "#" + uid("source:stig-xml")},
                      {"rel": "source", "href": "#" + uid("source:stig-mapping")},
                      {"rel": "source", "href": "#" + uid("source:nist-catalog")}],
            "remarks": (
                f"Generated by tools/executable_first_corpus.py from the STIG named in "
                f"back-matter ({release}, status {status}). Every rule becomes an "
                f"assessment objective on the SP 800-53 control its CCIs map to, "
                f"with DISA's check text as the body of an assessment method "
                f"beside it and DISA's fix text in a remediation part. The STIG "
                f"publishes the check as text, so the method names no engine and "
                f"no evaluation rule. The platform is the CPE the CIS Benchmark "
                f"publishes for the same operating system, because the STIG "
                f"carries none. The mapping from CCIs to controls is the one the "
                f"STIG's published OSCAL conversion derived from DISA's CCI list."),
        },
        "imports": [{"href": NIST_CATALOG_URL,
                     "include-controls": [{"with-ids": sorted(by_control)}]}],
        "merge": {"as-is": True},
        "modify": {"alters": alters},
        "back-matter": {"resources": [
            {"uuid": uid("source:stig-xml"),
             "title": f"{title}, {version}",
             "rlinks": [{"href": rel_from_out(STIG_XML), "media-type": "application/xml",
                         "hashes": [{"algorithm": "SHA-256",
                                     "value": sha256(STIG_XML)}]}]},
            {"uuid": uid("source:stig-mapping"),
             "title": "The STIG's published OSCAL conversion, source of the CCI "
                      "to control mapping",
             "rlinks": [{"href": rel_from_out(STIG_MAPPING),
                         "media-type": "application/oscal.assessment-plan+json",
                         "hashes": [{"algorithm": "SHA-256",
                                     "value": sha256(STIG_MAPPING)}]}]},
            {"uuid": uid("source:nist-catalog"),
             "title": "NIST SP 800-53 Revision 5 catalog",
             "rlinks": [{"href": NIST_CATALOG_URL,
                         "media-type": "application/oscal.catalog+json"}]},
        ]},
    }}


# --------------------------------------------------------------------------- #
# run                                                                          #
# --------------------------------------------------------------------------- #

def build_all() -> dict[str, dict]:
    bench = json.load(open(CIS_JSON, encoding="utf-8"))["Benchmark"]
    catalog, scripts, rules = build_cis(bench)
    files = {FILES["catalog"]: catalog}
    files.update(build_cis_profiles(bench, FILES["catalog"]))
    files[FILES["mapping"]] = build_mapping(bench, rules, FILES["catalog"])
    files[FILES["stig"]] = build_stig(bench["platforms"][0])
    files[FILES["rules"]] = build_rules_cdef(bench, rules, FILES["catalog"])
    return files


def render(doc) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def counts(files: dict[str, dict]) -> dict:
    """The figures the corpus carries, recomputed from the documents."""
    cat = files[FILES["catalog"]]["catalog"]
    ctls = []

    def walk(groups):
        for g in groups:
            ctls.extend(g.get("controls", []))
            walk(g.get("groups", []))

    walk(cat["groups"])
    methods = [p for c in ctls for p in c["parts"] if p["name"] == "assessment-method"]
    meth = collections.Counter(next(x["value"] for x in m["props"] if x["name"] == "method")
                               for m in methods)
    stig = files[FILES["stig"]]["profile"]
    objectives = sum(1 for a in stig["modify"]["alters"] for ad in a["adds"]
                     for p in ad.get("parts", []) if p["name"] == "assessment-objective")
    cdef = files[FILES["rules"]]["component-definition"]["components"][0]
    reqs = [r for ci in cdef["control-implementations"] for r in ci["implemented-requirements"]]
    scripts = [sc for r in reqs for sc in r.get("automation-scripts", [])]
    return {
        "rules_requirements": len(reqs),
        "rules_audit_scripts": sum(1 for sc in scripts if sc["script-type"] == "audit"),
        "rules_remediation_scripts": sum(1 for sc in scripts if sc["script-type"] == "remediation"),
        "rules_evaluated": sum(1 for sc in scripts if "evaluation-criteria" in sc),
        "rules_distinct_audit_scripts": len({sc["payload"] for sc in scripts
                                             if sc["script-type"] == "audit"}),
        "cis_controls": len(ctls),
        "cis_test": meth["TEST"],
        "cis_examine": meth["EXAMINE"],
        "cis_bash": sum(1 for m in methods
                        if any(p["name"] == "language" for p in m["props"])),
        "cis_evaluated": sum(1 for m in methods
                             if any(p["name"] == "evaluation" for p in m["props"])),
        "cis_params": sum(len(c.get("params", [])) for c in ctls),
        "cis_scripts": sum(1 for r in cat["back-matter"]["resources"]
                           if r.get("rlinks", [{}])[0].get("media-type") == "application/x-sh"),
        "cis_maps": len(files[FILES["mapping"]]["mapping-collection"]["mappings"][0]["maps"]),
        "stig_objectives": objectives,
        "stig_controls": len(stig["imports"][0]["include-controls"][0]["with-ids"]),
        "stig_alters": len(stig["modify"]["alters"]),
    }


#  Where trestle keeps each model inside a workspace. It validates only files
#  laid out this way, so the validator gets a temporary workspace with every
#  document copied into the directory its root element names.
TRESTLE_DIRS = {"catalog": "catalogs", "profile": "profiles",
                "mapping-collection": "mapping-collections",
                "component-definition": "component-definitions"}


def validate(files: dict[str, dict]) -> int:
    """Run an OSCAL validator over every file, if one is on the path."""
    exe = os.environ.get("TRESTLE") or shutil.which("trestle")
    if not exe:
        print("no OSCAL validator on the path (trestle); skipping validation")
        return 0
    import tempfile
    rc_all = 0
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([exe, "init"], cwd=tmp, capture_output=True, text=True)
        for name in sorted(files):
            root = next(iter(files[name]))
            rel = os.path.join(TRESTLE_DIRS[root], name[:-5], root + ".json")
            os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
            open(os.path.join(tmp, rel), "w", encoding="utf-8").write(render(files[name]))
            rc = subprocess.run([exe, "validate", "-f", rel], cwd=tmp,
                                capture_output=True, text=True)
            ok = rc.returncode == 0
            expected = (name not in EXPECT_INVALID) == ok
            rc_all |= 0 if expected else 1
            tail = (rc.stdout + rc.stderr).strip().splitlines()
            print(f"  {'VALID' if ok else 'INVALID'}"
                  f"{'' if expected else ' (NOT EXPECTED)'}"
                  f"{' (expected, a proposed assembly)' if not ok and expected else ''}"
                  f"  {name}" + ("" if ok else "  |  " + (tail[-1] if tail else "")))
    return rc_all


def main() -> int:
    files = build_all()
    if "--validate" in sys.argv:
        return validate(files)
    if "--check" in sys.argv:
        stale = [n for n, d in files.items()
                 if not os.path.isfile(os.path.join(OUT_DIR, n))
                 or open(os.path.join(OUT_DIR, n), encoding="utf-8").read() != render(d)]
        extra = sorted(set(os.listdir(OUT_DIR)) - set(files)) if os.path.isdir(OUT_DIR) else []
        if stale or extra:
            print(f"examples/executable-first/oscal is stale: {stale + extra}. "
                  f"Run tools/executable_first_corpus.py")
            return 1
        print(f"examples/executable-first/oscal is current, {len(files)} files")
        return 0
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, doc in files.items():
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(doc))
        print(f"  {name:64s} {os.path.getsize(os.path.join(OUT_DIR, name)):>9,} bytes")
    for k, v in counts(files).items():
        print(f"  {k:18s} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
