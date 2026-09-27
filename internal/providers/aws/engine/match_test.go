package engine

import (
	"slices"
	"strings"
	"testing"
)

// U1: action matching.
func TestMatchAction(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:Get*", "s3:GetObject", true},
		{"iam:*AccessKey*", "iam:ListAccessKeys", true},
		{"iam:*AccessKey*", "iam:ListUsers", false},
		{"s3:Get?bject", "s3:GetObject", true},
		{"s3:Get?bject", "s3:GetObjectX", false},
		{"*", "ec2:RunInstances", true},
		{"s3:*", "s3:PutObject", true},
		{"s3:*", "ec2:RunInstances", false},
		{"IAM:listaccesskeys", "iam:ListAccessKeys", true}, // AWS example: case-insensitive
		{"iam:ListAccessKeys", "IAM:LISTACCESSKEYS", true},
		{"s3:GetObject", "s3:GetObjectAcl", false},
		{"s3:GetObject", "s3:PutObject", false},
		{"", "s3:GetObject", false},
	}
	for _, tt := range tests {
		if got := matchAction(tt.pattern, tt.action); got != tt.want {
			t.Errorf("matchAction(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

// U2, U3, U4: resource matching per spec section 4.4.1.
func TestResourceMatch(t *testing.T) {
	tests := []struct {
		pattern  string
		version  string // "2012" or "2008"
		resource string
		want     resourceMatch
	}{
		// Worked examples from the specification.
		{"arn:aws:s3:::example-bucket/report.csv", "2012", "arn:aws:s3:::example-bucket/report.csv", resMatch},
		{"arn:aws:s3:::example-bucket/Report.csv", "2012", "arn:aws:s3:::example-bucket/report.csv", resNoMatch},
		{"arn:aws:s3:::example-bucket/*", "2012", "arn:aws:s3:::example-bucket/a/b/c.jpg", resMatch},
		{"arn:aws:s3:::example-bucket/*/test/*", "2012", "arn:aws:s3:::example-bucket/1/2/test/3/object.jpg", resMatch},
		{"arn:aws:s3:::example-bucket/*/test/*", "2012", "arn:aws:s3:::example-bucket/1-test/object.jpg", resNoMatch},
		{"arn:aws:s3:::example-bucket/????-test", "2012", "arn:aws:s3:::example-bucket/2024-test", resMatch},
		{"arn:aws:s3:::example-bucket/????-test", "2012", "arn:aws:s3:::example-bucket/12345-test", resNoMatch},
		{"arn:aws:ec2:*:111122223333:vpc/*", "2012", "arn:aws:ec2:us-east-1:111122223333:vpc/vpc-0abc", resMatch},
		{"arn:aws:ec2:us-*-1:111122223333:vpc/*", "2012", "arn:aws:ec2:us-east-1:111122223333:vpc/vpc-0abc", resMatch},
		{"arn:aws:ec2:us-*-1:111122223333:vpc/*", "2012", "arn:aws:ec2:us:x-1:111122223333:vpc/vpc-0abc", resNoMatch},
		{"arn:aws:logs:*:111122223333:log-group:app-*", "2012", "arn:aws:logs:us-east-1:111122223333:log-group:app-web:log-stream:1", resMatch},
		{"arn:aws:sqs", "2012", "arn:aws:sqs:us-east-1:111122223333:queue1", resMatch},
		{"*", "2012", "arn:aws:s3:::example-bucket/report.csv", resMatch},
		{"*", "2012", "*", resMatch},
		{"arn:aws:s3:::*", "2012", "*", resNoMatch},
		{"arn:aws:sqs", "2012", "*", resNoMatch},
		{"arn:aws:s3:::bucket/${*}", "2012", "arn:aws:s3:::bucket/*", resMatch},
		{"arn:aws:s3:::bucket/${*}", "2012", "arn:aws:s3:::bucket/report.csv", resNoMatch},
		// Additional U2 cases.
		{"arn:aws:s3:::x", "2012", "arn:aws:s3:::x", resMatch},                           // empty segments
		{"arn:aws:s3:::x", "2012", "arn:aws:s3:::xy", resNoMatch},                        // exact means whole string
		{"arn:aws:ec2:*-*-1:1:vpc/*", "2012", "arn:aws:ec2:us-east-1:1:vpc/v", resMatch}, // multiple * in a segment
		{"arn:aws:ec2:us-east-?:1:vpc/v", "2012", "arn:aws:ec2:us-east-1:1:vpc/v", resMatch},
		{"arn:aws:logs:us-east-1:1:log-group:a?b", "2012", "arn:aws:logs:us-east-1:1:log-group:a:b", resNoMatch}, // ? never matches ':'
		{"arn:aws:logs:us-east-1:1:log-group:a*b", "2012", "arn:aws:logs:us-east-1:1:log-group:a:b", resNoMatch}, // mid-segment * never matches ':'
		{"arn:aws:logs:us-east-1:1:log-group:*", "2012", "arn:aws:logs:us-east-1:1:log-group:a:b", resMatch},     // trailing * at end
		{"arn:aws:ec2:*:1:vpc/v", "2012", "arn:aws:ec2:us:east:1:vpc/v", resMatch},                               // trailing * before ':' crosses
		{"arn:aws:s3:::bucket/?", "2012", "arn:aws:s3:::bucket/é", resMatch},                                     // ? is one code point
		{"arn:aws:s3:::bucket/??", "2012", "arn:aws:s3:::bucket/é", resNoMatch},
		{"arn:aws:s3:::bucket/*", "2012", "arn:aws:s3:::other/x", resNoMatch},
		// U3: incomplete ARN completion.
		{"arn:aws:ec2:us-east-1", "2012", "arn:aws:ec2:us-east-1:1:vpc/v", resMatch},
		{"arn:aws:ec2:us-east-1", "2012", "arn:aws:ec2:us-west-2:1:vpc/v", resNoMatch},
		{"arn:aws:sqs", "2012", "arn:aws:sns:us-east-1:1:t", resNoMatch},
		// U4: special variables.
		{"arn:aws:s3:::bucket/a${?}b", "2012", "arn:aws:s3:::bucket/a?b", resMatch},
		{"arn:aws:s3:::bucket/a${?}b", "2012", "arn:aws:s3:::bucket/axb", resNoMatch},
		{"arn:aws:s3:::bucket/price${$}", "2012", "arn:aws:s3:::bucket/price$", resMatch},
		{"arn:aws:s3:::bucket/${*}", "2008", "arn:aws:s3:::bucket/${*}", resMatch},  // literal text, * a wildcard
		{"arn:aws:s3:::bucket/${*}", "2008", "arn:aws:s3:::bucket/${xy}", resMatch}, // * inside literal text is a wildcard
		// U5: other policy variables.
		{"arn:aws:s3:::bucket/${aws:username}", "2012", "arn:aws:s3:::bucket/alice", resUnresolvable},
		{"arn:aws:s3:::bucket/${aws:PrincipalTag/team, 'x'}", "2012", "arn:aws:s3:::bucket/x", resUnresolvable},
		{"arn:aws:s3:::bucket/${aws:username}", "2008", "arn:aws:s3:::bucket/${aws:username}", resMatch},
		{"arn:aws:s3:::bucket/${aws:username}", "2008", "arn:aws:s3:::bucket/alice", resNoMatch},
		{"arn:aws:s3:::bucket/${aws:username}", "2012", "*", resNoMatch}, // request "*" only matched by "*"
	}
	for _, tt := range tests {
		p, err := compileResource(tt.pattern, tt.version == "2012")
		if err != nil {
			t.Errorf("compileResource(%q): %v", tt.pattern, err)
			continue
		}
		if got := p.match(tt.resource); got != tt.want {
			t.Errorf("%s pattern %q vs %q = %v, want %v", tt.version, tt.pattern, tt.resource, got, tt.want)
		}
	}
}

func TestCompileResourceErrors(t *testing.T) {
	tests := []struct {
		pattern string
		v2012   bool
		want    string
	}{
		{"arn:aws:s*:::x", true, "partition or service"},
		{"arn:aws:*:us-east-1:1:queue1", true, "partition or service"},
		{"arn:a?s:s3:::x", true, "partition or service"},
		{"arn:aws:s3:::x", true, ""},
		{"arn:aws:s3:${aws:region}::x", true, "before the fifth colon"},
		{"arn:aws:s3:::bucket/${aws:username", true, "unterminated"},
		{"arn:aws:s3:${aws:region}::x", false, ""}, // literal in 2008
		{"s3:::x", true, "must be"},
	}
	for _, tt := range tests {
		_, err := compileResource(tt.pattern, tt.v2012)
		if tt.want == "" {
			if err != nil {
				t.Errorf("compileResource(%q) unexpected error %v", tt.pattern, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("compileResource(%q) error = %v, want %q", tt.pattern, err, tt.want)
		}
	}
}

func TestUnresolvableVariablesRecorded(t *testing.T) {
	p, err := compileResource("arn:aws:s3:::b/${aws:username}/${aws:PrincipalTag/team}", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"aws:username", "aws:PrincipalTag/team"}; !slices.Equal(p.unresolvable, want) {
		t.Errorf("unresolvable = %v, want %v", p.unresolvable, want)
	}
}

func TestValidateAction(t *testing.T) {
	for _, ok := range []string{"s3:GetObject", "aws-portal:ViewBilling", "ec2:RunInstances"} {
		if err := validateAction(ok); err != nil {
			t.Errorf("validateAction(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"s3:Get*", "s3:Get?bject", "*", "s3", ":GetObject", "s3:", "s3:Get-Object", "s3:Get:Object"} {
		if err := validateAction(bad); err == nil {
			t.Errorf("validateAction(%q) = nil, want error", bad)
		}
	}
}
