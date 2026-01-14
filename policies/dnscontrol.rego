package dnscontrol

import future.keywords.if

# -----------------------------------------------------------------------------
# DNSControl OPA policy
# -----------------------------------------------------------------------------
# Expected input shape:
# {
#   "zones": [
#     {
#       "name": "example.com",
#       "records": [
#         { "name": "www", "type": "A", "ttl": 300, "value": "1.2.3.4" },
#         { "name": "@",   "type": "MX", "ttl": 3600, "value": "10 mail.example.com." }
#       ]
#     }
#   ]
# }
#
# Outputs:
# - deny[msg] : hard failures
# - warn[msg] : soft warnings
# -----------------------------------------------------------------------------

# --------------------------
# Config (tweak as you like)
# --------------------------

default min_ttl := 300
default max_ttl := 86400

# Zones you never want modified by this pipeline (examples):
# - "prod.example.com"
# - "example.com"  (apex)
protected_zone_exact := {
  # "example.com",
  # "prod.example.com",
}

# Zone name prefixes you want protected (examples: "prod.", "corp.", etc.)
protected_zone_prefixes := {
  "prod.",
}

# Record types you allow at all (tighten or expand as needed)
allowed_types := {
  "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR",
}

# For "external CNAME target" checks (warn), set your internal suffixes
internal_suffixes := {
  ".example.com",
  ".example.net",
}

# --------------------------
# Helpers
# --------------------------

zones := input.zones if input.zones else []

records[zone_name] := rec {
  zone := zones[_]
  zone_name := zone.name
  rec := zone.records[_]
}

is_protected_zone(zone_name) {
  protected_zone_exact[zone_name]
} else {
  some p
  p := protected_zone_prefixes[_]
  startswith(zone_name, p)
}

# Normalize record name (treat missing name as empty string)
record_name(r) := n {
  n := r.name
} else := "" {
  not r.name
}

record_ttl(r) := t {
  t := r.ttl
} else := 0 {
  not r.ttl
}

record_value(r) := v {
  v := r.value
} else := "" {
  not r.value
}

is_apex_name(n) {
  n == "@"
} else {
  n == ""
}

is_wildcard_name(n) {
  n == "*"
} else {
  startswith(n, "*.")
}

has_trailing_dot(s) {
  endswith(s, ".")
}

# very light hostname-ish check (keeps policy from being overly strict)
looks_like_fqdn(s) {
  contains(s, ".")
}

# --------------------------
# DENY rules (hard failures)
# --------------------------

# 1) TTL too low
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  ttl := record_ttl(r)
  ttl > 0
  ttl < min_ttl
  msg := sprintf("TTL too low (%v) in zone %v for %v %v", [ttl, zone.name, r.type, record_name(r)])
}

# 2) TTL too high (optional but useful to keep hygiene)
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  ttl := record_ttl(r)
  ttl > max_ttl
  msg := sprintf("TTL too high (%v) in zone %v for %v %v (max %v)", [ttl, zone.name, r.type, record_name(r), max_ttl])
}

# 3) Wildcard records forbidden
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  is_wildcard_name(record_name(r))
  msg := sprintf("Wildcard record not allowed in zone %v: %v %v", [zone.name, r.type, record_name(r)])
}

# 4) Protected zones cannot be modified (deny any presence of records for protected zone)
# NOTE: If you want "read-only unless approved", you can gate this on an input flag or CI context.
deny[msg] {
  zone := zones[_]
  is_protected_zone(zone.name)
  count(zone.records) > 0
  msg := sprintf("Protected zone cannot be modified by this pipeline: %v", [zone.name])
}

# 5) CNAME at apex forbidden
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  r.type == "CNAME"
  is_apex_name(record_name(r))
  msg := sprintf("CNAME not allowed at zone apex in %v", [zone.name])
}

# 6) Record type allowlist
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  not allowed_types[r.type]
  msg := sprintf("Record type %v is not allowed (zone %v name %v)", [r.type, zone.name, record_name(r)])
}

# 7) CNAME target should look like an FQDN (basic sanity)
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  r.type == "CNAME"
  v := record_value(r)
  v != ""
  not looks_like_fqdn(v)
  msg := sprintf("CNAME target does not look like a hostname: zone %v name %v -> %v", [zone.name, record_name(r), v])
}

# 8) MX target should be a hostname (and preference should exist if you encode it separately)
# If your DNSControl JSON encodes MX value as "10 mail.example.com." this will just sanity-check the hostname-ish portion.
deny[msg] {
  zone := zones[_]
  r := zone.records[_]
  r.type == "MX"
  v := record_value(r)
  v != ""
  not contains(v, ".")
  msg := sprintf("MX target does not look like a hostname: zone %v name %v -> %v", [zone.name, record_name(r), v])
}

# --------------------------
# WARN rules (soft warnings)
# --------------------------

# A) Multiple A records for same name (within the same zone)
warn[msg] {
  zone := zones[_]
  name := zone.records[_].name
  name != null

  count([r |
    r := zone.records[_]
    r.type == "A"
    record_name(r) == name
  ]) > 1

  msg := sprintf("multiple A records detected in zone %v for name %v", [zone.name, name])
}

# B) External CNAME targets (supply-chain / SaaS dependency awareness)
warn[msg] {
  zone := zones[_]
  r := zone.records[_]
  r.type == "CNAME"

  v := record_value(r)
  v != ""

  # if it ends with any internal suffix, it's internal; otherwise warn
  not is_internal_target(v)

  msg := sprintf("external CNAME target detected in zone %v: %v -> %v", [zone.name, record_name(r), v])
}

is_internal_target(v) {
  some s
  s := internal_suffixes[_]
  endswith(lower(v), lower(s))
}

# C) Hostname targets without trailing dot (often fine, but can be a style inconsistency)
warn[msg] {
  zone := zones[_]
  r := zone.records[_]
  r.type == "CNAME" or r.type == "MX" or r.type == "NS" or r.type == "SRV"

  v := record_value(r)
  v != ""
  looks_like_fqdn(v)
  not has_trailing_dot(v)

  msg := sprintf("target missing trailing dot in zone %v for %v %v -> %v", [zone.name, r.type, record_name(r), v])
}
