#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fnmatch
import json
import sys
import re
from collections import defaultdict
import argparse

# --- Default soggetti "ovvi" da ignorare (meno rumore, stessi segnali utili) ---
DEFAULT_IGNORED_SUBJECT_SIDS = {
    "S-1-5-10",       # Principal Self
    #"S-1-1-0",        # Everyone
    "S-1-5-18",       # Local System
    "S-1-3-0",        # Creator Owner
    "S-1-5-11",       # Authenticated Users
    "S-1-5-32-545",   # BUILTIN\Users
    "S-1-5-32-544",    # BUILTIN\Administrators
    "S-1-5-21-*-512",  # Domain Admins (pattern: * = domain RID)
    "S-1-5-21-*-519",  # Enterprise Admins
    "S-1-5-21-*-518",  # Schema Admins
    "S-1-5-21-*-516",  # Domain Controllers
}
DEFAULT_IGNORED_NAME_PATTERNS = []  # es: [r'^Test', r'^Servizio_']

SELF_ONLY_EXTENDED_RIGHTS = {"user-change-password"}  # semantica "self" lato DC

def is_self_only_semantic_for_everyone(trustee_sid, ace):
    if trustee_sid != "S-1-1-0":  # Everyone
        return False
    objt = (ace.get("ObjectAceType") or "").lower()
    return objt in SELF_ONLY_EXTENDED_RIGHTS


def is_ignored(trustee_sid, ignore_sids):
    for pattern in ignore_sids:
        if fnmatch.fnmatch(trustee_sid, pattern):
            return True
    return False




# ----- Heuristics per una categoria "power" utile in AD pentest/IR -----
def classify_power(ace):
    rights = set(ace.get("ADRights", []) or [])
    obj_type = (ace.get("ObjectAceType") or "").lower()

    if "GENERIC_ALL" in rights:
        return "FullControl"
    if "WRITE_DACL" in rights and "WRITE_OWNER" in rights:
        return "TakeoverCandidate"
    if "WRITE_DACL" in rights:
        return "CanEditACL"
    if "WRITE_OWNER" in rights:
        return "CanTakeOwnership"
    if "DELETE" in rights and "DELETE_TREE" in rights:
        return "CanDeleteTree"
    if "DELETE" in rights:
        return "CanDelete"

    if obj_type == "user-change-password":
        return "ResetPassword"
    if obj_type == "validated-spn":
        return "WriteSPN"
    if obj_type == "dns-host-name-attributes":
        return "WriteDNSHostName"
    if obj_type == "ds-validated-write-compute":
        return "ValidatedWrite"
    if obj_type == "private-information":
        return "PrivateInfoRW"

    if "WRITE_PROPERTY" in rights:
        return "WriteProperty"
    if "READ_PROPERTY" in rights:
        return "ReadProperty"
    if "EXTENDED_RIGHTS" in rights:
        return "ExtendedRights"
    return "Other"

def norm_tuple(entry):
    rights = tuple(sorted(entry.get("ADRights", []) or []))
    return (
        entry.get("TargetSid"),
        entry.get("AceType"),
        rights,
        (entry.get("ObjectAceType") or ""),
    )

def build_name_regex(patterns):
    if not patterns:
        return None
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)

def invert_acls(objs, ignore_sids, ignore_name_regex):
    inverted = {}
    target_index = {o.get("Sid"): {"Name": o.get("Name"), "DN": o.get("DN")} for o in objs}
    tmp = defaultdict(list)

    for o in objs:
        target_sid = o.get("Sid")
        target_name = o.get("Name")
        target_dn = o.get("DN")
        for ace in (o.get("Dacl") or []):
            trustee_sid = ace.get("ObjectSid")
            trustee_name = ace.get("Name") or ""
            # filtro soggetti ovvi
            if is_ignored(trustee_sid, ignore_sids):
                continue
            if ignore_name_regex and ignore_name_regex.search(trustee_name):
                continue

            if is_self_only_semantic_for_everyone(trustee_sid, ace):
                continue

            entry = {
                "TargetSid": target_sid,
                "TargetName": target_name,
                "TargetDN": target_dn,
                "AceType": ace.get("AceType"),
                "AccessMask": ace.get("AccessMask"),
                "ADRights": ace.get("ADRights") or [],
                "IsInherited": bool(ace.get("IsInherited")),
                "ObjectAceType": ace.get("ObjectAceType"),
                "InheritedObjectType": ace.get("InheritedObjectType"),
                "Power": classify_power(ace),
            }
            tmp[(trustee_sid, trustee_name)].append(entry)

    for (sid, name), entries in tmp.items():
        seen = {}
        for e in entries:
            key = norm_tuple(e)
            if key not in seen:
                seen[key] = e
            else:
                seen[key]["IsInherited"] = seen[key]["IsInherited"] or e["IsInherited"]
        final_list = list(seen.values())
        final_list.sort(key=lambda x: (x.get("TargetName") or "", x.get("Power") or "", x.get("AceType") or ""))
        inverted[sid] = {"Sid": sid, "Name": name, "Targets": final_list}

    return inverted

def print_human(inverted):
    for sid, info in inverted.items():
        name = info.get("Name") or "(unknown)"
        targets = info.get("Targets") or []
        if not targets:
            continue
        print("=" * 100)
        print("SUBJECT: %s  (%s)" % (name, sid))
        print("Controlla %d oggetto/i" % len(targets))
        cur_header = None
        for t in targets:
            header = "%s  |  %s" % (t.get("TargetName") or t.get("TargetSid"), t.get("TargetDN") or "")
            if header != cur_header:
                print("-" * 100)
                print(header)
                cur_header = header
            adr = ",".join(t.get("ADRights") or [])
            objt = t.get("ObjectAceType") or ""
            inh = "inherited" if t.get("IsInherited") else "explicit"
            print("  - %-16s  %-18s  rights=[%s]  objType=%s  %s" % (
                t.get("Power"),
                t.get("AceType"),
                adr,
                objt,
                inh,
            ))

def parse_args():
    p = argparse.ArgumentParser(description="Inverti ACL AD: soggetto -> target (con filtro soggetti ovvi).")
    p.add_argument("input", help="File JSON input (lista di oggetti con Dacl)")
    p.add_argument("output", nargs="?", default="inverted_acls.json", help="File JSON output")
    p.add_argument("--ignore-sid", action="append", default=[], help="SID da ignorare (ripetibile)")
    p.add_argument("--ignore-name", action="append", default=[], help="Regex nome da ignorare (ripetibile)")
    p.add_argument("--no-default-ignores", action="store_true", help="Non usare gli ignore di default")
    return p.parse_args()

def rev(data, ignore_sid=None, ignore_name=None, no_default_ignores=False):
    ignore_sids = set(ignore_sid or [])
    ignore_name_patterns = list(ignore_name or [])

    if not no_default_ignores:
        ignore_sids |= DEFAULT_IGNORED_SUBJECT_SIDS
        ignore_name_patterns.extend(DEFAULT_IGNORED_NAME_PATTERNS)

    ignore_name_regex = build_name_regex(ignore_name_patterns)
    inverted = invert_acls(data, ignore_sids, ignore_name_regex)

    return inverted

def main():
    args = parse_args()

    ignore_sids = args.ignore_sid
    ignore_name_patterns = args.ignore_name
    no_default_ignores = args.no_default_ignores

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    inverted = rev(data, ignore_sids, ignore_name_patterns, no_default_ignores)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(inverted, f, indent=2, ensure_ascii=False)

    print_human(inverted)
    print("\nSalvato JSON invertito in: %s" % args.output)

def mainz():
    args = parse_args()

    ignore_sids = set(args.ignore_sid or [])
    ignore_name_patterns = list(args.ignore_name or [])

    if not args.no_default_ignores:
        ignore_sids |= DEFAULT_IGNORED_SUBJECT_SIDS
        ignore_name_patterns.extend(DEFAULT_IGNORED_NAME_PATTERNS)

    ignore_name_regex = build_name_regex(ignore_name_patterns)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    inverted = invert_acls(data, ignore_sids, ignore_name_regex)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(inverted, f, indent=2, ensure_ascii=False)

    print_human(inverted)
    print("\nSalvato JSON invertito in: %s" % args.output)

if __name__ == "__main__":
    mainz()
