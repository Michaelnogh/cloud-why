package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Michaelnogh/cloud-why/internal/investigation"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	roleFixture  = "../../testdata/aws/role-app.json"
	userFixture  = "../../testdata/aws/user-alice.json"
	roleARN      = "arn:aws:iam::111122223333:role/app"
	userARN      = "arn:aws:iam::111122223333:user/alice"
	reportObject = "arn:aws:s3:::example-bucket/reports/q3.csv"
	secretObject = "arn:aws:s3:::example-bucket/secret/keys.txt"
)

func runCLI(args ...string) (stdout, stderr string, code int) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return out.String(), errb.String(), code
}

func explainArgs(snapshot, principal, action, resource, output string) []string {
	return []string{"explain", "--snapshot", snapshot, "--principal", principal, "--action", action, "--resource", resource, "--output", output}
}

// Golden cases cover every verdict and both output formats. Fixtures use the
// GetAccountAuthorizationDetails response shape with URL-encoded documents
// (role-app.json) and plain JSON documents (user-alice.json).
var goldenCases = []struct {
	name                                  string
	snapshot, principal, action, resource string
	code                                  int
	verdict                               investigation.Verdict
}{
	{"role-allowed", roleFixture, roleARN, "s3:GetObject", reportObject, exitAllowed, investigation.Allowed},
	{"role-denied-explicit", roleFixture, roleARN, "s3:GetObject", secretObject, exitDeniedExplicit, investigation.DeniedExplicit},
	{"role-denied-implicit", roleFixture, roleARN, "s3:PutObject", reportObject, exitDeniedImplicit, investigation.DeniedImplicit},
	{"role-request-star", roleFixture, roleARN, "s3:ListAllMyBuckets", "*", exitAllowed, investigation.Allowed},
	{"user-unknown-condition", userFixture, userARN, "s3:PutObject", "arn:aws:s3:::example-bucket/uploads/a.txt", exitUnknown, investigation.Unknown},
	{"user-denied-explicit-group", userFixture, userARN, "iam:CreateUser", "arn:aws:iam::111122223333:user/bob", exitDeniedExplicit, investigation.DeniedExplicit},
	{"principal-not-in-snapshot", roleFixture, "arn:aws:iam::111122223333:role/other", "s3:GetObject", reportObject, exitUnknown, investigation.Unknown},
}

func TestGolden(t *testing.T) {
	for _, gc := range goldenCases {
		for _, format := range []string{"json", "text"} {
			t.Run(gc.name+"."+format, func(t *testing.T) {
				out, errOut, code := runCLI(explainArgs(gc.snapshot, gc.principal, gc.action, gc.resource, format)...)
				if code != gc.code {
					t.Fatalf("exit code %d, want %d; stderr: %s", code, gc.code, errOut)
				}
				if errOut != "" {
					t.Errorf("unexpected stderr: %s", errOut)
				}
				if format == "json" {
					var r investigation.Result
					if err := json.Unmarshal([]byte(out), &r); err != nil {
						t.Fatal(err)
					}
					if r.Verdict != gc.verdict {
						t.Errorf("verdict %s, want %s", r.Verdict, gc.verdict)
					}
				} else if !strings.Contains(out, "Evaluation scope: AWS identity-based policies only") {
					t.Errorf("text output does not state the evaluation scope")
				}
				ext := map[string]string{"json": ".json", "text": ".txt"}[format]
				golden := filepath.Join("..", "..", "testdata", "golden", gc.name+ext)
				if *update {
					if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("read golden (run with -update to create): %v", err)
				}
				if out != string(want) {
					t.Errorf("output differs from %s\n--- got ---\n%s", golden, out)
				}
			})
		}
	}
}

// P01 at CLI level.
func TestDeterministicOutput(t *testing.T) {
	for _, gc := range goldenCases {
		for _, format := range []string{"json", "text"} {
			a, _, _ := runCLI(explainArgs(gc.snapshot, gc.principal, gc.action, gc.resource, format)...)
			b, _, _ := runCLI(explainArgs(gc.snapshot, gc.principal, gc.action, gc.resource, format)...)
			if a != b {
				t.Errorf("%s/%s: output differs between runs", gc.name, format)
			}
		}
	}
}

func TestProvenance(t *testing.T) {
	out, _, _ := runCLI(explainArgs(roleFixture, roleARN, "s3:GetObject", reportObject, "json")...)
	var r investigation.Result
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(roleFixture)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Provenance
	if p.Input.Bytes != int64(len(data)) || len(p.Input.SHA256) != 64 || p.Input.Path != roleFixture {
		t.Errorf("input provenance = %+v", p.Input)
	}
	if p.ProviderContacted || p.NetworkUsed || p.CollectedAt != nil || p.Account != "111122223333" {
		t.Errorf("provenance = %+v", p)
	}
	if !strings.Contains(out, `"collected_at": null`) {
		t.Errorf("collected_at must be null")
	}
}

// E01, E03, E12 to E15: CLI input errors and exit codes.
func TestInputErrors(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSnapshotBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", nil, "Usage"},
		{"unknown subcommand", []string{"whoami"}, "Usage"},
		{"E14 missing --snapshot", []string{"explain", "--principal", roleARN, "--action", "s3:GetObject", "--resource", "*"}, "missing --snapshot"},
		{"missing --resource", []string{"explain", "--snapshot", roleFixture, "--principal", roleARN, "--action", "s3:GetObject"}, "missing --resource"},
		{"unknown flag", []string{"explain", "--verify-provider"}, "flag provided but not defined"},
		{"extra argument", append(explainArgs(roleFixture, roleARN, "s3:GetObject", "*", "text"), "extra"), "unexpected argument"},
		{"bad output", explainArgs(roleFixture, roleARN, "s3:GetObject", "*", "yaml"), "--output must be"},
		{"missing file", explainArgs("../../testdata/aws/does-not-exist.json", roleARN, "s3:GetObject", "*", "text"), "no such file"},
		{"E01 invalid JSON", explainArgs("../../testdata/aws/invalid-json.json", roleARN, "s3:GetObject", "*", "text"), "snapshot:"},
		{"E03 malformed URL encoding", explainArgs("../../testdata/aws/malformed-encoding.json", roleARN, "s3:GetObject", "*", "text"), "malformed URL encoding"},
		{"E12 wildcard action", explainArgs(roleFixture, roleARN, "s3:Get*", "*", "text"), "action must be"},
		{"E13 short resource", explainArgs(roleFixture, roleARN, "s3:GetObject", "arn:aws:s3", "text"), "resource must be"},
		{"input over 64 MiB", explainArgs(big, roleARN, "s3:GetObject", "*", "text"), "larger than 64 MiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, errOut, code := runCLI(tt.args...)
			if code != exitInputError {
				t.Fatalf("exit code %d, want %d", code, exitInputError)
			}
			if out != "" {
				t.Errorf("stdout must be empty on input error, got %q", out)
			}
			if !strings.Contains(errOut, tt.want) {
				t.Errorf("stderr %q, want containing %q", errOut, tt.want)
			}
		})
	}
}

// E15: the approved exit code values.
func TestExitCodeValues(t *testing.T) {
	want := map[string]int{"ALLOWED": 0, "INTERNAL": 1, "INPUT": 2, "DENIED_EXPLICIT": 3, "DENIED_IMPLICIT": 4, "UNKNOWN": 5}
	got := map[string]int{"ALLOWED": exitAllowed, "INTERNAL": exitInternalError, "INPUT": exitInputError,
		"DENIED_EXPLICIT": exitDeniedExplicit, "DENIED_IMPLICIT": exitDeniedImplicit, "UNKNOWN": exitUnknown}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("exit code for %s = %d, want %d", k, got[k], v)
		}
	}
}
