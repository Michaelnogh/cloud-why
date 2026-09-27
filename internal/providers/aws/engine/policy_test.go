package engine

import (
	"strings"
	"testing"
)

// U6: policy grammar (spec section 4.2).
func TestParsePolicyValid(t *testing.T) {
	tests := []struct {
		name       string
		doc        string
		statements int
		single     bool
		version    string
	}{
		{"statement object, action string", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`, 1, true, "2012-10-17"},
		{"statement array, action array", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["*"]},{"Effect":"Deny","NotAction":"iam:*","NotResource":"arn:aws:s3:::b"}]}`, 2, false, "2012-10-17"},
		{"version 2008", `{"Version":"2008-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, 1, true, "2008-10-17"},
		{"version absent, Id and Sid", `{"Id":"x","Statement":[{"Sid":"S1","Effect":"Allow","Action":"*","Resource":"*","Condition":{}}]}`, 1, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parsePolicy([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			if len(p.statements) != tt.statements || p.single != tt.single || p.version != tt.version {
				t.Errorf("got %d statements single=%v version=%q", len(p.statements), p.single, p.version)
			}
		})
	}
}

func TestParsePolicyInvalid(t *testing.T) {
	stmt := func(s string) string { return `{"Version":"2012-10-17","Statement":[` + s + `]}` }
	tests := []struct {
		name, doc, want string
	}{
		{"not an object", `[]`, "JSON object"},
		{"unknown top-level key", `{"Statement":[],"Extra":1}`, `unknown policy element "Extra"`},
		{"bad version", `{"Version":"2020-01-01","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, "unsupported Version"},
		{"version not string", `{"Version":1,"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, "Version must be a string"},
		{"missing Statement", `{"Version":"2012-10-17"}`, "missing Statement"},
		{"empty Statement array", `{"Statement":[]}`, "must not be empty"},
		{"Statement string", `{"Statement":"x"}`, "object or an array"},
		{"E05 Effect lowercase", stmt(`{"Effect":"allow","Action":"*","Resource":"*"}`), "Effect must be exactly"},
		{"missing Effect", stmt(`{"Action":"*","Resource":"*"}`), "missing Effect"},
		{"E06 Action and NotAction", stmt(`{"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"}`), "both Action and NotAction"},
		{"neither Action nor NotAction", stmt(`{"Effect":"Allow","Resource":"*"}`), "must contain Action or NotAction"},
		{"E07 neither Resource nor NotResource", stmt(`{"Effect":"Allow","Action":"*"}`), "must contain Resource or NotResource"},
		{"Resource and NotResource", stmt(`{"Effect":"Allow","Action":"*","Resource":"*","NotResource":"*"}`), "both Resource and NotResource"},
		{"E08 Principal", stmt(`{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}`), "Principal is not valid"},
		{"NotPrincipal", stmt(`{"Effect":"Allow","NotPrincipal":"*","Action":"*","Resource":"*"}`), "NotPrincipal is not valid"},
		{"E09 unknown statement key", stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Foo":1}`), `unknown statement element "Foo"`},
		{"empty action list", stmt(`{"Effect":"Allow","Action":[],"Resource":"*"}`), "must not be empty"},
		{"action not service:action", stmt(`{"Effect":"Allow","Action":"s3GetObject","Resource":"*"}`), "must be"},
		{"action number", stmt(`{"Effect":"Allow","Action":5,"Resource":"*"}`), "string or an array"},
		{"resource not an ARN", stmt(`{"Effect":"Allow","Action":"*","Resource":"bucket"}`), "must be"},
		{"Condition not an object", stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":[]}`), "Condition must be an object"},
		{"Sid not a string", stmt(`{"Sid":1,"Effect":"Allow","Action":"*","Resource":"*"}`), "Sid must be a string"},
		{"E10 wildcard in service field", stmt(`{"Effect":"Allow","Action":"*","Resource":"arn:aws:s*:::x"}`), "partition or service"},
		{"duplicate statement key", stmt(`{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}`), `duplicate key "Effect"`},
		{"duplicate top-level key", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"},"Statement":[]}`, `duplicate key "Statement"`},
		{"duplicate key inside Condition", stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"a":"1"},"Bool":{"b":"2"}}}`), `duplicate key "Bool"`},
		{"E11 variable before fifth colon", stmt(`{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:${aws:region}::x"}`), "before the fifth colon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePolicy([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestStatementLocation(t *testing.T) {
	p, _ := parsePolicy([]byte(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`))
	if got := p.location(p.statements[0]); got != "/Statement" {
		t.Errorf("single statement location = %q", got)
	}
	p, _ = parsePolicy([]byte(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`))
	if got := p.location(p.statements[1]); got != "/Statement/1" {
		t.Errorf("array statement location = %q", got)
	}
}
