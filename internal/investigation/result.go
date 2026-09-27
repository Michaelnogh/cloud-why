// Package investigation defines the Common Investigation Result: the
// provider-neutral output contract shared by all cloud-why provider engines.
//
// It is an output contract only. It contains no policy model and no
// evaluation logic. Provider-specific facts appear as native strings,
// provider-prefixed identifiers, or inside Step.Detail.
package investigation

// Schema identifies the result format. v0 is a draft; a stable, versioned
// schema is planned for CW-004.
const Schema = "cloud-why.investigation.v0"

// Verdict is the answer to the investigation question within its scope.
type Verdict string

const (
	Allowed        Verdict = "ALLOWED"
	DeniedExplicit Verdict = "DENIED_EXPLICIT"
	DeniedImplicit Verdict = "DENIED_IMPLICIT"
	Unknown        Verdict = "UNKNOWN"
)

// Effect is the effect of an evidence source.
type Effect string

const (
	EffectAllow Effect = "ALLOW"
	EffectDeny  Effect = "DENY"
	EffectNone  Effect = "NONE"
)

// Outcome is how an evidence source related to the question.
type Outcome string

const (
	Matched       Outcome = "MATCHED"
	NotMatched    Outcome = "NOT_MATCHED"
	NotEvaluated  Outcome = "NOT_EVALUATED"
	NotApplicable Outcome = "NOT_APPLICABLE"
)

// GapReason classifies why something was not evaluated.
type GapReason string

const (
	Unsupported GapReason = "UNSUPPORTED"
	MissingData GapReason = "MISSING_DATA"
	NotReadable GapReason = "NOT_READABLE"
	OutOfScope  GapReason = "OUT_OF_SCOPE"
)

// Scope lists the provider-defined layers the verdict covers.
type Scope struct {
	Layers []string `json:"layers"`
	Label  string   `json:"label"`
}

// Question is the access question, in native provider vocabulary.
type Question struct {
	Provider  string            `json:"provider"`
	Principal string            `json:"principal"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Context   map[string]string `json:"context"`
	Scope     Scope             `json:"scope"`
}

// Source identifies the document and location an evidence step refers to.
type Source struct {
	Kind     string `json:"kind"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Via      string `json:"via,omitempty"`
	Location string `json:"location,omitempty"`
	Label    string `json:"label,omitempty"`
}

// Step is one evaluated source, in evaluation order.
type Step struct {
	Step        int            `json:"step"`
	Layer       string         `json:"layer"`
	Source      Source         `json:"source"`
	Effect      Effect         `json:"effect"`
	Outcome     Outcome        `json:"outcome"`
	Decisive    bool           `json:"decisive"`
	Reasons     []string       `json:"reasons"`
	Explanation []string       `json:"explanation"`
	Detail      map[string]any `json:"detail,omitempty"`
}

// Gap is something that was not evaluated.
type Gap struct {
	Layer          string    `json:"layer"`
	Reason         GapReason `json:"reason"`
	Code           string    `json:"code"`
	Detail         string    `json:"detail"`
	Source         *Source   `json:"source,omitempty"`
	AffectsVerdict bool      `json:"affects_verdict"`
}

// InputProvenance describes the local input the result was computed from.
type InputProvenance struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Bytes       int64  `json:"bytes"`
	Format      string `json:"format"`
	IsTruncated bool   `json:"is_truncated"`
}

// Provenance records where the data came from. CollectedAt is nil when the
// input does not carry a collection time; it is never invented.
type Provenance struct {
	Input             InputProvenance `json:"input"`
	CollectedAt       *string         `json:"collected_at"`
	Account           string          `json:"account,omitempty"`
	ProviderContacted bool            `json:"provider_contacted"`
	NetworkUsed       bool            `json:"network_used"`
	ToolVersion       string          `json:"tool_version"`
	Engine            string          `json:"engine"`
}

// Result is the Common Investigation Result.
type Result struct {
	Schema     string     `json:"schema"`
	Question   Question   `json:"question"`
	Verdict    Verdict    `json:"verdict"`
	Evidence   []Step     `json:"evidence"`
	Gaps       []Gap      `json:"gaps"`
	Provenance Provenance `json:"provenance"`
}
