package aws.mgmt.api

import rego.v1

default allow := false
default reason := "denied by default policy"

# Permitted baseline actions per role (enforced in UTC so local DST transitions do not shift windows)
role_allowed_actions := {
	"platform-sre": {"iam:AttachRolePolicy", "iam:DetachRolePolicy", "sts:AssumeRole"},
	"security-auditor": {"sts:AssumeRole"},
	"break-glass-responder": {"iam:AttachRolePolicy", "iam:DetachRolePolicy", "sts:AssumeRole"},
}

# Break-glass override requires an active incident ID (>= 6 chars) and explicit justification (>= 10 chars)
break_glass_valid if {
	input.break_glass.enabled == true
	count(input.break_glass.incident_id) >= 6
	count(input.break_glass.justification) >= 10
	input.role in {"platform-sre", "break-glass-responder"}
}

allow if {
	break_glass_valid
	input.action in role_allowed_actions[input.role]
}

allow if {
	not break_glass_valid
	input.action in role_allowed_actions[input.role]
	valid_operating_window
}

valid_operating_window if {
	input.utc_hour >= 5
	input.utc_hour <= 22
}

reason := "allowed via verified break-glass incident override" if {
	allow
	break_glass_valid
}

reason := "allowed within UTC operating window" if {
	allow
	not break_glass_valid
}

reason := "denied: action not permitted for role or outside UTC operating window" if {
	not allow
}
