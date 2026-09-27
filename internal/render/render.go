// Package render prints a Common Investigation Result as JSON or text.
// It computes no decisions; it only presents what the engine produced.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Michaelnogh/cloud-why/internal/investigation"
)

// JSON writes the result as indented JSON followed by a newline.
func JSON(w io.Writer, r investigation.Result) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// verdictMeaning is provider-neutral text explaining a verdict relative to
// the evaluated scope.
var verdictMeaning = map[investigation.Verdict]string{
	investigation.Allowed:        "Allowed within the evaluated scope. This does not guarantee that the real request succeeds: layers outside the scope were not evaluated.",
	investigation.DeniedExplicit: "An applicable explicit deny was found within the evaluated scope.",
	investigation.DeniedImplicit: "Nothing within the evaluated scope allows the request. Layers outside the scope were not evaluated and could still grant access.",
	investigation.Unknown:        "Missing or unsupported information could change the result within the evaluated scope. See the gaps.",
}

// Text writes a human-readable report.
func Text(w io.Writer, r investigation.Result) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	mode := "offline"
	if r.Provenance.ProviderContacted || r.Provenance.NetworkUsed {
		mode = "online"
	}
	p("cloud-why explain (%s: provider contacted: %s, network used: %s)\n\n",
		mode, yesNo(r.Provenance.ProviderContacted), yesNo(r.Provenance.NetworkUsed))

	p("Question\n")
	p("  provider   %s\n", r.Question.Provider)
	p("  principal  %s\n", r.Question.Principal)
	p("  action     %s\n", r.Question.Action)
	p("  resource   %s\n", r.Question.Resource)
	p("Evaluation scope: %s\n\n", r.Question.Scope.Label)

	p("Verdict: %s\n", r.Verdict)
	p("  %s\n\n", verdictMeaning[r.Verdict])

	p("Evidence\n")
	if len(r.Evidence) == 0 {
		p("  (none)\n")
	}
	for _, s := range r.Evidence {
		decisive := ""
		if s.Decisive {
			decisive = "  [decisive]"
		}
		p("  %d. %s %s  %s %q %s%s\n", s.Step, s.Outcome, s.Effect, s.Source.Kind, s.Source.Name, s.Source.Location, decisive)
		p("     source   %s\n", s.Source.ID)
		if s.Source.Version != "" {
			p("     version  %s\n", s.Source.Version)
		}
		if s.Source.Via != "" {
			p("     via      %s\n", s.Source.Via)
		}
		if s.Source.Label != "" {
			p("     label    %s\n", s.Source.Label)
		}
		p("     reasons  %s\n", strings.Join(s.Reasons, ", "))
		for _, l := range s.Explanation {
			p("     - %s\n", l)
		}
	}
	p("\n")

	p("Gaps\n")
	for _, g := range r.Gaps {
		affects := "does not affect verdict"
		if g.AffectsVerdict {
			affects = "AFFECTS VERDICT"
		}
		p("  %s  %s  %s  (%s)\n", g.Layer, g.Reason, g.Code, affects)
		p("     %s\n", g.Detail)
	}
	p("\n")

	pr := r.Provenance
	p("Provenance\n")
	p("  input               %s\n", pr.Input.Path)
	p("  sha256              %s\n", pr.Input.SHA256)
	p("  bytes               %d\n", pr.Input.Bytes)
	p("  format              %s\n", pr.Input.Format)
	p("  truncated           %s\n", yesNo(pr.Input.IsTruncated))
	collected := "unknown"
	if pr.CollectedAt != nil {
		collected = *pr.CollectedAt
	}
	p("  collected at        %s\n", collected)
	if pr.Account != "" {
		p("  account             %s\n", pr.Account)
	}
	p("  provider contacted  %s\n", yesNo(pr.ProviderContacted))
	p("  network used        %s\n", yesNo(pr.NetworkUsed))
	p("  engine              %s\n", pr.Engine)
	p("  tool version        %s\n", pr.ToolVersion)

	_, err := io.WriteString(w, b.String())
	return err
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
