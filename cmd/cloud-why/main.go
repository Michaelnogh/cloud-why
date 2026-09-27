// Command cloud-why explains AWS authorization decisions offline.
//
// CW-001 supports one subcommand:
//
//	cloud-why explain --snapshot FILE --principal ARN --action SERVICE:ACTION --resource ARN|* [--output text|json]
//
// It reads one local file and contacts no provider.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Michaelnogh/cloud-why/internal/investigation"
	"github.com/Michaelnogh/cloud-why/internal/providers/aws/engine"
	"github.com/Michaelnogh/cloud-why/internal/providers/aws/snapshot"
	"github.com/Michaelnogh/cloud-why/internal/render"
)

// version is set at release time with -ldflags.
var version = "dev"

// Exit codes (CW-001 specification, approved).
const (
	exitAllowed        = 0
	exitInternalError  = 1
	exitInputError     = 2
	exitDeniedExplicit = 3
	exitDeniedImplicit = 4
	exitUnknown        = 5
)

// maxSnapshotBytes is the input size limit (64 MiB).
const maxSnapshotBytes = 64 << 20

const usage = `Usage:
  cloud-why explain --snapshot FILE --principal ARN --action SERVICE:ACTION --resource ARN|* [--output text|json]

Explains, offline, whether the AWS identity-based policies in FILE allow the
action for the principal on the resource. FILE is a
GetAccountAuthorizationDetails response, for example the output of
"aws iam get-account-authorization-details". Nothing contacts AWS.

--resource "*" is a literal request value for actions without resource-level
permissions. It does not mean "any resource".

Exit codes: 0 ALLOWED, 1 internal error, 2 input error, 3 DENIED_EXPLICIT,
4 DENIED_IMPLICIT, 5 UNKNOWN.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "cloud-why: internal error: %v\n", r)
			code = exitInternalError
		}
	}()

	if len(args) == 0 || args[0] != "explain" {
		fmt.Fprint(stderr, usage)
		return exitInputError
	}

	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	snapPath := fs.String("snapshot", "", "path to a GetAccountAuthorizationDetails JSON file")
	principal := fs.String("principal", "", "IAM user or role ARN")
	action := fs.String("action", "", "action, for example s3:GetObject")
	resource := fs.String("resource", "", `resource ARN, or "*" for actions without resource-level permissions`)
	output := fs.String("output", "text", "output format: text or json")
	if err := fs.Parse(args[1:]); err != nil {
		return exitInputError
	}
	if fs.NArg() > 0 {
		return inputError(stderr, fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}
	required := []struct{ name, value string }{
		{"snapshot", *snapPath}, {"principal", *principal}, {"action", *action}, {"resource", *resource},
	}
	for _, f := range required {
		if f.value == "" {
			fmt.Fprint(stderr, usage)
			return inputError(stderr, fmt.Errorf("missing --%s", f.name))
		}
	}
	if *output != "text" && *output != "json" {
		return inputError(stderr, fmt.Errorf("--output must be text or json"))
	}

	data, err := readSnapshot(*snapPath)
	if err != nil {
		return inputError(stderr, err)
	}
	sum := sha256.Sum256(data)

	snap, err := snapshot.Parse(data)
	if err != nil {
		return inputError(stderr, err)
	}
	result, err := engine.Explain(snap,
		engine.Question{Principal: *principal, Action: *action, Resource: *resource},
		investigation.InputProvenance{Path: *snapPath, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))},
		version)
	if err != nil {
		if engine.IsInputError(err) {
			return inputError(stderr, err)
		}
		fmt.Fprintf(stderr, "cloud-why: internal error: %v\n", err)
		return exitInternalError
	}

	if *output == "json" {
		err = render.JSON(stdout, result)
	} else {
		err = render.Text(stdout, result)
	}
	if err != nil {
		fmt.Fprintf(stderr, "cloud-why: internal error: %v\n", err)
		return exitInternalError
	}

	switch result.Verdict {
	case investigation.Allowed:
		return exitAllowed
	case investigation.DeniedExplicit:
		return exitDeniedExplicit
	case investigation.DeniedImplicit:
		return exitDeniedImplicit
	case investigation.Unknown:
		return exitUnknown
	}
	fmt.Fprintf(stderr, "cloud-why: internal error: unexpected verdict %q\n", result.Verdict)
	return exitInternalError
}

func readSnapshot(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotBytes {
		return nil, errors.New("snapshot is larger than 64 MiB")
	}
	return data, nil
}

func inputError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "cloud-why: input error: %v\n", err)
	return exitInputError
}
