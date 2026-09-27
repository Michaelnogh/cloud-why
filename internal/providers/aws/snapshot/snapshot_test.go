package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty object: all lists empty", `{}`, false},
		{"unknown fields ignored", `{"UserDetailList":[{"Arn":"arn:aws:iam::1:user/a","CreateDate":"2013-10-14T18:32:24Z","Tags":[]}],"Marker":"x"}`, false},
		{"truncated flag", `{"IsTruncated":true}`, false},
		{"E01 invalid JSON", `{"UserDetailList":[`, true},
		{"top level array", `[]`, true},
		{"top level null", `null`, true},
		{"empty input", ``, true},
		{"E02 UserDetailList is an object", `{"UserDetailList":{}}`, true},
		{"GroupList wrong type", `{"UserDetailList":[{"GroupList":"developers"}]}`, true},
		{"IsDefaultVersion wrong type", `{"Policies":[{"PolicyVersionList":[{"IsDefaultVersion":"true"}]}]}`, true},
		{"trailing data", `{} {}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestParseReadsFields(t *testing.T) {
	d, err := Parse([]byte(`{
		"UserDetailList":[{"Arn":"arn:aws:iam::1:user/a","UserName":"a","GroupList":["g"],
			"UserPolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[]}}],
			"AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::1:policy/m"}],
			"PermissionsBoundary":{"PermissionsBoundaryType":"Policy","PermissionsBoundaryArn":"arn:aws:iam::1:policy/b"}}],
		"Policies":[{"Arn":"arn:aws:iam::1:policy/m","PolicyVersionList":[{"VersionId":"v2","IsDefaultVersion":true,"Document":"%7B%7D"}]}],
		"IsTruncated":true}`))
	if err != nil {
		t.Fatal(err)
	}
	u := d.UserDetailList[0]
	if u.GroupList[0] != "g" || u.UserPolicyList[0].PolicyName != "p" || u.AttachedManagedPolicies[0].PolicyArn != "arn:aws:iam::1:policy/m" {
		t.Errorf("user fields not read: %+v", u)
	}
	if u.PermissionsBoundary == nil || u.PermissionsBoundary.PermissionsBoundaryArn != "arn:aws:iam::1:policy/b" {
		t.Errorf("boundary not read")
	}
	if !d.IsTruncated || d.Policies[0].PolicyVersionList[0].VersionId != "v2" {
		t.Errorf("policy fields not read")
	}
}

// U7: policy document normalization.
func TestNormalizeDocument(t *testing.T) {
	plain := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/a+b c"}}`
	tests := []struct {
		name     string
		raw      string
		wantJSON string
		wantEnc  string
		wantErr  string
	}{
		{name: "plain JSON object", raw: plain, wantJSON: plain, wantEnc: EncodingJSONObject},
		{
			name:     "RFC 3986 URL-encoded string",
			raw:      `"` + "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22arn%3Aaws%3As3%3A%3A%3Ab%2Fa+b%20c%22%7D%7D" + `"`,
			wantJSON: plain, // '+' stays '+', %20 becomes a space
			wantEnc:  EncodingURLEncoded,
		},
		{name: "plus is not decoded to space", raw: `"%7B%22a%22%3A%22x+y%22%7D"`, wantJSON: `{"a":"x+y"}`, wantEnc: EncodingURLEncoded},
		{name: "malformed escape", raw: `"%zz"`, wantErr: "malformed URL encoding"},
		{name: "truncated escape", raw: `"%7B%22Version%2"`, wantErr: "malformed URL encoding"},
		{name: "decoded invalid UTF-8", raw: `"%7B%22a%22%3A%22%FF%FE%22%7D"`, wantErr: "not valid UTF-8"},
		{name: "decoded text not JSON", raw: `"hello"`, wantErr: "not a JSON object"},
		{name: "decoded JSON array", raw: `"%5B%5D"`, wantErr: "not a JSON object"},
		{name: "decoded broken JSON object", raw: `"%7B%22a%22"`, wantErr: "not a JSON object"},
		{name: "missing", raw: ``, wantErr: "missing"},
		{name: "null", raw: `null`, wantErr: "must be a JSON object or a URL-encoded JSON string"},
		{name: "number", raw: `42`, wantErr: "must be a JSON object or a URL-encoded JSON string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := NormalizeDocument(json.RawMessage(tt.raw))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(doc.JSON) != tt.wantJSON || doc.Encoding != tt.wantEnc {
				t.Errorf("got %s (%s), want %s (%s)", doc.JSON, doc.Encoding, tt.wantJSON, tt.wantEnc)
			}
		})
	}
}

// Decoding happens exactly once: an encoded percent sign stays a literal '%'.
func TestNormalizeDecodesOnce(t *testing.T) {
	doc, err := NormalizeDocument(json.RawMessage(`"%7B%22a%22%3A%22100%2541%22%7D"`))
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.JSON) != `{"a":"100%41"}` {
		t.Errorf("got %s", doc.JSON)
	}
}
