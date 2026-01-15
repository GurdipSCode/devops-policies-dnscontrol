package dnscontrol_test

import data.dnscontrol.deny

#
# Helpers
#

# Convenience: run deny with given input
deny_with_input(input) = result {
  result := deny with input as input
}

#
# Test cases
#

# ------------------------------------------------
# ALLOW CASES
# ------------------------------------------------

test_allow_valid_a_record {
  input := {
    "records": [
      {
        "type": "A",
        "name": "www",
        "value": "192.0.2.10",
        "ttl": 300
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  count(violations) == 0
}

test_allow_valid_cname {
  input := {
    "records": [
      {
        "type": "CNAME",
        "name": "app",
        "value": "app.netlify.app",
        "ttl": 300
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  count(violations) == 0
}

# ------------------------------------------------
# DENY CASES
# ------------------------------------------------

test_deny_missing_ttl {
  input := {
    "records": [
      {
        "type": "A",
        "name": "api",
        "value": "192.0.2.20"
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  count(violations) == 1
}

test_deny_invalid_ip {
  input := {
    "records": [
      {
        "type": "A",
        "name": "bad",
        "value": "999.999.999.999",
        "ttl": 300
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  some v
  v := deny_with_input(input)[_]
  contains(v, "invalid IP")
}

test_deny_wildcard_record {
  input := {
    "records": [
      {
        "type": "A",
        "name": "*",
        "value": "192.0.2.30",
        "ttl": 300
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  count(violations) > 0
}

test_deny_short_ttl {
  input := {
    "records": [
      {
        "type": "A",
        "name": "fast",
        "value": "192.0.2.40",
        "ttl": 30
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  some v
  v := violations[_]
  contains(v, "TTL")
}

# ------------------------------------------------
# EDGE CASES
# ------------------------------------------------

test_deny_empty_records {
  input := {
    "records": [],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  count(violations) == 1
}

test_deny_missing_zone {
  input := {
    "records": [
      {
        "type": "A",
        "name": "www",
        "value": "192.0.2.50",
        "ttl": 300
      }
    ]
  }

  violations := deny_with_input(input)
  count(violations) == 1
}

test_deny_unknown_record_type {
  input := {
    "records": [
      {
        "type": "TXT",
        "name": "weird",
        "value": "hello",
        "ttl": 300
      }
    ],
    "zone": "example.com"
  }

  violations := deny_with_input(input)
  some v
  v := violations[_]
  contains(v, "unsupported record type")
}
