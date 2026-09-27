// Package engine evaluates one AWS authorization question against the
// identity-based policies in a snapshot (cloud-why CW-001).
//
// All AWS authorization semantics live here. The engine is a pure function
// over in-memory data: it performs no file, clock or network access.
package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Michaelnogh/cloud-why/internal/investigation"
	"github.com/Michaelnogh/cloud-why/internal/providers/aws/snapshot"
)

const (
	// Name identifies this engine in provenance.
	Name = "aws.identity/cw-001"

	layerIdentity = "aws.identity"
	scopeLabel    = "AWS identity-based policies only"

	decisiveDenyLine = "An applicable explicit Deny overrides any Allow. This deny is decisive for the final AWS authorization decision."
	truncationNote   = " The snapshot is truncated (IsTruncated is true); the missing item may be in a later page."
)

// Reason codes recorded on evidence steps.
const (
	ActionMatched             = "ACTION_MATCHED"
	ActionNotMatched          = "ACTION_NOT_MATCHED"
	NotActionExcluded         = "NOTACTION_EXCLUDED"
	NotActionNotExcluded      = "NOTACTION_NOT_EXCLUDED"
	ResourceMatched           = "RESOURCE_MATCHED"
	ResourceNotMatched        = "RESOURCE_NOT_MATCHED"
	NotResourceExcluded       = "NOTRESOURCE_EXCLUDED"
	NotResourceNotExcluded    = "NOTRESOURCE_NOT_EXCLUDED"
	ResourceNotChecked        = "RESOURCE_NOT_CHECKED"
	PolicyVariableUnresolved  = "POLICY_VARIABLE_UNRESOLVABLE"
	ConditionAbsent           = "CONDITION_ABSENT"
	ConditionNotEvaluated     = "CONDITION_NOT_EVALUATED"
	ConditionNotChecked       = "CONDITION_NOT_CHECKED"
	PrincipalTypeNotSupported = "PRINCIPAL_TYPE_NOT_SUPPORTED"
	PrincipalNotInSnapshot    = "PRINCIPAL_NOT_IN_SNAPSHOT"
	ManagedPolicyMissing      = "MANAGED_POLICY_NOT_IN_SNAPSHOT"
	DefaultVersionMissing     = "DEFAULT_VERSION_NOT_IN_SNAPSHOT"
	GroupMissing              = "GROUP_NOT_IN_SNAPSHOT"
	LayerNotInCW001           = "LAYER_NOT_IN_CW001"
)

// Question is the request to explain, in AWS vocabulary.
type Question struct {
	Principal string
	Action    string
	Resource  string
}

// InputError reports invalid input: the question, the snapshot or a policy
// document. The CLI maps it to exit code 2.
type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

func inputErr(format string, a ...any) error {
	return &InputError{Err: fmt.Errorf(format, a...)}
}

// stepDetail is the AWS-only structured detail of an evidence step.
type stepDetail struct {
	PolicyVersionElement   string   `json:"policy_version_element"`
	DocumentEncoding       string   `json:"document_encoding"`
	ActionElement          string   `json:"action_element"`
	ActionMatchedPattern   string   `json:"action_matched_pattern,omitempty"`
	ResourceElement        string   `json:"resource_element"`
	ResourceMatchedPattern string   `json:"resource_matched_pattern,omitempty"`
	UnresolvableVariables  []string `json:"unresolvable_variables,omitempty"`
	Condition              string   `json:"condition"`
}

// Explain evaluates q against the identity-based policies in s.
// in carries the caller-observed input facts (path, sha256, size).
func Explain(s *snapshot.AuthorizationDetails, q Question, in investigation.InputProvenance, toolVersion string) (investigation.Result, error) {
	if err := validateQuestion(q); err != nil {
		return investigation.Result{}, err
	}
	in.Format = snapshot.Format
	in.IsTruncated = s.IsTruncated

	e := &evaluation{snap: s, q: q}
	principalAccount := arnField(q.Principal, 4)
	e.run()
	if e.err != nil {
		return investigation.Result{}, e.err
	}
	verdict := e.finish()

	gaps := e.gaps
	gaps = append(gaps, outOfScopeGaps(q, principalAccount, e.boundary)...)

	return investigation.Result{
		Schema: investigation.Schema,
		Question: investigation.Question{
			Provider:  "aws",
			Principal: q.Principal,
			Action:    q.Action,
			Resource:  q.Resource,
			Context:   map[string]string{},
			Scope: investigation.Scope{
				Layers: []string{layerIdentity},
				Label:  scopeLabel,
			},
		},
		Verdict:  verdict,
		Evidence: e.steps,
		Gaps:     gaps,
		Provenance: investigation.Provenance{
			Input:       in,
			Account:     principalAccount,
			ToolVersion: toolVersion,
			Engine:      Name,
		},
	}, nil
}

func validateQuestion(q Question) error {
	if !strings.HasPrefix(q.Principal, "arn:") || strings.Count(q.Principal, ":") < 5 {
		return inputErr("principal must be an ARN with six colon-separated fields")
	}
	if err := validateAction(q.Action); err != nil {
		return &InputError{Err: err}
	}
	if q.Resource != "*" && (!strings.HasPrefix(q.Resource, "arn:") || strings.Count(q.Resource, ":") < 5) {
		return inputErr("resource must be \"*\" or an ARN with six colon-separated fields")
	}
	return nil
}

// evaluation holds the state of one Explain call.
type evaluation struct {
	snap *snapshot.AuthorizationDetails
	q    Question
	err  error

	steps    []investigation.Step
	gaps     []investigation.Gap
	boundary string // permissions boundary ARN of the principal, if any

	// Per-step and per-gap bookkeeping for the verdict.
	stepEffect []string // "Allow" or "Deny" per step
	gapKind    []gapKind
	principal  bool // principal-level gap: verdict UNKNOWN
}

type gapKind uint8

const (
	gapPrincipal gapKind = iota
	gapMissing
	gapAllowNotEvaluated
	gapDenyNotEvaluated
)

type source struct {
	kind, id, name, version, via string
}

func (e *evaluation) run() {
	parts := strings.SplitN(e.q.Principal, ":", 6)
	supported := len(parts) == 6 && parts[2] == "iam" &&
		(strings.HasPrefix(parts[5], "user/") || strings.HasPrefix(parts[5], "role/"))
	if !supported {
		e.addGap(gapPrincipal, investigation.Gap{
			Layer:  layerIdentity,
			Reason: investigation.Unsupported,
			Code:   PrincipalTypeNotSupported,
			Detail: fmt.Sprintf("CW-001 supports IAM users and roles only; %s is not an IAM user or role ARN.", e.q.Principal),
		})
		return
	}

	for i := range e.snap.UserDetailList {
		u := &e.snap.UserDetailList[i]
		if u.Arn != e.q.Principal {
			continue
		}
		if u.PermissionsBoundary != nil {
			e.boundary = u.PermissionsBoundary.PermissionsBoundaryArn
		}
		for _, p := range u.UserPolicyList {
			e.evalInline(source{kind: "aws.user_inline_policy", id: u.Arn, name: p.PolicyName}, p)
		}
		for _, a := range u.AttachedManagedPolicies {
			e.evalManaged(source{kind: "aws.user_managed_policy"}, u.Arn, a)
		}
		for _, name := range u.GroupList {
			g := e.findGroup(name)
			if g == nil {
				e.addGap(gapMissing, investigation.Gap{
					Layer:  layerIdentity,
					Reason: investigation.MissingData,
					Code:   GroupMissing,
					Detail: fmt.Sprintf("User %s is a member of group %q, which is not in the snapshot's GroupDetailList.", u.Arn, name) + e.truncation(),
				})
				continue
			}
			for _, p := range g.GroupPolicyList {
				e.evalInline(source{kind: "aws.group_inline_policy", id: g.Arn, name: p.PolicyName, via: g.Arn}, p)
			}
			for _, a := range g.AttachedManagedPolicies {
				e.evalManaged(source{kind: "aws.group_managed_policy", via: g.Arn}, g.Arn, a)
			}
		}
		return
	}

	for i := range e.snap.RoleDetailList {
		r := &e.snap.RoleDetailList[i]
		if r.Arn != e.q.Principal {
			continue
		}
		if r.PermissionsBoundary != nil {
			e.boundary = r.PermissionsBoundary.PermissionsBoundaryArn
		}
		for _, p := range r.RolePolicyList {
			e.evalInline(source{kind: "aws.role_inline_policy", id: r.Arn, name: p.PolicyName}, p)
		}
		for _, a := range r.AttachedManagedPolicies {
			e.evalManaged(source{kind: "aws.role_managed_policy"}, r.Arn, a)
		}
		return
	}

	e.addGap(gapPrincipal, investigation.Gap{
		Layer:  layerIdentity,
		Reason: investigation.MissingData,
		Code:   PrincipalNotInSnapshot,
		Detail: fmt.Sprintf("Principal %s is not in the snapshot's UserDetailList or RoleDetailList.", e.q.Principal) + e.truncation(),
	})
}

func (e *evaluation) findGroup(name string) *snapshot.GroupDetail {
	for i := range e.snap.GroupDetailList {
		if e.snap.GroupDetailList[i].GroupName == name {
			return &e.snap.GroupDetailList[i]
		}
	}
	return nil
}

func (e *evaluation) truncation() string {
	if e.snap.IsTruncated {
		return truncationNote
	}
	return ""
}

func (e *evaluation) evalInline(src source, p snapshot.InlinePolicy) {
	if e.err != nil {
		return
	}
	doc, err := snapshot.NormalizeDocument(p.PolicyDocument)
	if err != nil {
		e.err = inputErr("%s %q of %s: %v", src.kind, src.name, src.id, err)
		return
	}
	e.evalDocument(src, doc)
}

// evalManaged resolves a managed policy attachment to its default version.
// AWS: the default version "is the operative version"; other versions have
// no effect.
func (e *evaluation) evalManaged(src source, owner string, a snapshot.AttachedPolicy) {
	if e.err != nil {
		return
	}
	src.id = a.PolicyArn
	src.name = a.PolicyName
	gapSrc := &investigation.Source{Kind: src.kind, ID: a.PolicyArn, Name: a.PolicyName, Via: src.via}

	var mp *snapshot.ManagedPolicyDetail
	for i := range e.snap.Policies {
		if e.snap.Policies[i].Arn == a.PolicyArn {
			mp = &e.snap.Policies[i]
			break
		}
	}
	if mp == nil {
		e.addGap(gapMissing, investigation.Gap{
			Layer:  layerIdentity,
			Reason: investigation.MissingData,
			Code:   ManagedPolicyMissing,
			Detail: fmt.Sprintf("Managed policy %s is attached to %s but is not in the snapshot's Policies list.", a.PolicyArn, owner) + e.truncation(),
			Source: gapSrc,
		})
		return
	}
	if mp.PolicyName != "" {
		src.name = mp.PolicyName
		gapSrc.Name = mp.PolicyName
	}
	for _, v := range mp.PolicyVersionList {
		if !v.IsDefaultVersion {
			continue
		}
		src.version = v.VersionId
		doc, err := snapshot.NormalizeDocument(v.Document)
		if err != nil {
			e.err = inputErr("%s %s version %s: %v", src.kind, a.PolicyArn, v.VersionId, err)
			return
		}
		e.evalDocument(src, doc)
		return
	}
	e.addGap(gapMissing, investigation.Gap{
		Layer:  layerIdentity,
		Reason: investigation.MissingData,
		Code:   DefaultVersionMissing,
		Detail: fmt.Sprintf("Managed policy %s has no version with IsDefaultVersion true in the snapshot.", a.PolicyArn),
		Source: gapSrc,
	})
}

func (e *evaluation) evalDocument(src source, doc snapshot.Document) {
	p, err := parsePolicy(doc.JSON)
	if err != nil {
		e.err = inputErr("%s %q (%s): invalid IAM policy: %v", src.kind, src.name, src.id, err)
		return
	}
	for _, st := range p.statements {
		e.evalStatement(src, doc, p, st)
	}
}

// evalStatement applies spec section 4.6 to one statement.
func (e *evaluation) evalStatement(src source, doc snapshot.Document, p *policy, st statement) {
	versionElement := p.version
	if versionElement == "" {
		versionElement = "absent"
	}
	d := stepDetail{
		PolicyVersionElement: versionElement,
		DocumentEncoding:     doc.Encoding,
		ActionElement:        "Action",
		ResourceElement:      "Resource",
	}
	if st.notAction {
		d.ActionElement = "NotAction"
	}
	if st.notResource {
		d.ResourceElement = "NotResource"
	}

	step := investigation.Step{
		Step:  len(e.steps) + 1,
		Layer: layerIdentity,
		Source: investigation.Source{
			Kind:     src.kind,
			ID:       src.id,
			Name:     src.name,
			Version:  src.version,
			Via:      src.via,
			Location: p.location(st),
			Label:    st.sid,
		},
		Effect: investigation.EffectAllow,
	}
	if st.effect == "Deny" {
		step.Effect = investigation.EffectDeny
	}

	// Step 1: action element.
	covered, reason, line, pattern := e.actionCoverage(st)
	d.ActionMatchedPattern = pattern
	step.Reasons = append(step.Reasons, reason)
	step.Explanation = append(step.Explanation, line)
	if !covered {
		step.Outcome = investigation.NotMatched
		step.Reasons = append(step.Reasons, ResourceNotChecked, ConditionNotChecked)
		step.Explanation = append(step.Explanation, "resource not checked: the action element does not cover the action", "condition not checked")
		d.Condition = "not-checked"
		e.addStep(step, d, st.effect)
		return
	}

	// Steps 2 and 3: resource element.
	rc := e.resourceCoverage(st)
	d.ResourceMatchedPattern = rc.pattern
	d.UnresolvableVariables = rc.variables
	step.Reasons = append(step.Reasons, rc.reason)
	step.Explanation = append(step.Explanation, rc.line)
	if rc.state == coverNo {
		step.Outcome = investigation.NotMatched
		step.Reasons = append(step.Reasons, ConditionNotChecked)
		step.Explanation = append(step.Explanation, "condition not checked")
		d.Condition = "not-checked"
		e.addStep(step, d, st.effect)
		return
	}

	// Step 4: condition.
	if st.hasCondition {
		step.Reasons = append(step.Reasons, ConditionNotEvaluated)
		step.Explanation = append(step.Explanation, "Condition element present; CW-001 does not evaluate conditions")
		d.Condition = "present-not-evaluated"
	} else {
		step.Reasons = append(step.Reasons, ConditionAbsent)
		step.Explanation = append(step.Explanation, "no Condition element")
		d.Condition = "absent"
	}

	if rc.state == coverUnknown || st.hasCondition {
		step.Outcome = investigation.NotEvaluated
		idx := e.addStep(step, d, st.effect)
		kind := gapAllowNotEvaluated
		if st.effect == "Deny" {
			kind = gapDenyNotEvaluated
		}
		gs := e.steps[idx].Source
		if rc.state == coverUnknown {
			e.addGap(kind, investigation.Gap{
				Layer:  layerIdentity,
				Reason: investigation.Unsupported,
				Code:   PolicyVariableUnresolved,
				Detail: fmt.Sprintf("Statement %s of %s %q: resource coverage depends on policy variable(s) %s, whose values come from the request context, which CW-001 does not have.",
					gs.Location, gs.Kind, gs.Name, formatVars(rc.variables)),
				Source: &gs,
			})
		}
		if st.hasCondition {
			e.addGap(kind, investigation.Gap{
				Layer:  layerIdentity,
				Reason: investigation.Unsupported,
				Code:   ConditionNotEvaluated,
				Detail: fmt.Sprintf("Statement %s of %s %q has a Condition element; CW-001 does not evaluate conditions.", gs.Location, gs.Kind, gs.Name),
				Source: &gs,
			})
		}
		return
	}

	step.Outcome = investigation.Matched
	e.addStep(step, d, st.effect)
}

// actionCoverage applies Action or NotAction semantics.
func (e *evaluation) actionCoverage(st statement) (covered bool, reason, line, pattern string) {
	for _, a := range st.actions {
		if matchAction(a, e.q.Action) {
			if st.notAction {
				return false, NotActionExcluded,
					fmt.Sprintf("action %s matches NotAction pattern %q: the statement does not apply to this action", e.q.Action, a), a
			}
			return true, ActionMatched, fmt.Sprintf("action %s matches Action pattern %q", e.q.Action, a), a
		}
	}
	if st.notAction {
		return true, NotActionNotExcluded,
			fmt.Sprintf("action %s matches no NotAction pattern %s: the statement applies to this action, subject to its resource element and condition", e.q.Action, quoteList(st.actions)), ""
	}
	return false, ActionNotMatched, fmt.Sprintf("action %s matches no Action pattern %s", e.q.Action, quoteList(st.actions)), ""
}

type coverState uint8

const (
	coverNo coverState = iota
	coverYes
	coverUnknown
)

type resourceCover struct {
	state     coverState
	reason    string
	line      string
	pattern   string
	variables []string
}

// resourceCoverage applies Resource or NotResource semantics (spec 4.4.2).
func (e *evaluation) resourceCoverage(st statement) resourceCover {
	r := e.q.Resource
	var unresolvable []string
	for _, rp := range st.resources {
		switch rp.match(r) {
		case resMatch:
			if st.notResource {
				return resourceCover{state: coverNo, reason: NotResourceExcluded, pattern: rp.raw,
					line: fmt.Sprintf("resource %s matches NotResource pattern %q: the statement does not apply to this resource", r, rp.raw)}
			}
			return resourceCover{state: coverYes, reason: ResourceMatched, pattern: rp.raw,
				line: fmt.Sprintf("resource %s matches Resource pattern %q", r, rp.raw)}
		case resUnresolvable:
			unresolvable = append(unresolvable, rp.unresolvable...)
		}
	}
	if len(unresolvable) > 0 {
		return resourceCover{state: coverUnknown, reason: PolicyVariableUnresolved, variables: unresolvable,
			line: fmt.Sprintf("resource %s: coverage depends on policy variable(s) %s from the request context, which CW-001 does not have", r, formatVars(unresolvable))}
	}
	var patterns []string
	for _, rp := range st.resources {
		patterns = append(patterns, rp.raw)
	}
	if st.notResource {
		return resourceCover{state: coverYes, reason: NotResourceNotExcluded,
			line: fmt.Sprintf("resource %s matches no NotResource pattern %s: the statement applies to this resource", r, quoteList(patterns))}
	}
	return resourceCover{state: coverNo, reason: ResourceNotMatched,
		line: fmt.Sprintf("resource %s matches no Resource pattern %s", r, quoteList(patterns))}
}

func (e *evaluation) addStep(step investigation.Step, d stepDetail, effect string) int {
	step.Detail = map[string]any{"aws": d}
	e.steps = append(e.steps, step)
	e.stepEffect = append(e.stepEffect, effect)
	return len(e.steps) - 1
}

func (e *evaluation) addGap(kind gapKind, g investigation.Gap) {
	if kind == gapPrincipal {
		e.principal = true
	}
	e.gaps = append(e.gaps, g)
	e.gapKind = append(e.gapKind, kind)
}

// finish combines statement outcomes (spec 4.7), then sets decisive flags and
// affects_verdict.
func (e *evaluation) finish() investigation.Verdict {
	var D, Du, A, Au, M bool
	for i, s := range e.steps {
		deny := e.stepEffect[i] == "Deny"
		switch {
		case s.Outcome == investigation.Matched && deny:
			D = true
		case s.Outcome == investigation.NotEvaluated && deny:
			Du = true
		case s.Outcome == investigation.Matched:
			A = true
		case s.Outcome == investigation.NotEvaluated:
			Au = true
		}
	}
	for _, k := range e.gapKind {
		if k == gapMissing {
			M = true
		}
	}

	v := combine(e.principal, D, Du, M, A, Au)

	// A gap affects the verdict if resolving it, alone or together with the
	// other open gaps, could change the verdict within the question's scope.
	denyOpen := !D
	allowOpen := !D && !A
	for i, k := range e.gapKind {
		switch k {
		case gapPrincipal:
			e.gaps[i].AffectsVerdict = true
		case gapMissing, gapDenyNotEvaluated:
			e.gaps[i].AffectsVerdict = denyOpen
		case gapAllowNotEvaluated:
			e.gaps[i].AffectsVerdict = allowOpen
		}
	}

	for i := range e.steps {
		s := &e.steps[i]
		deny := e.stepEffect[i] == "Deny"
		switch {
		case v == investigation.DeniedExplicit && s.Outcome == investigation.Matched && deny:
			s.Decisive = true
			s.Explanation = append(s.Explanation, decisiveDenyLine)
		case v == investigation.Allowed && s.Outcome == investigation.Matched && !deny:
			s.Decisive = true
		case v == investigation.Unknown && s.Outcome == investigation.NotEvaluated:
			s.Decisive = (deny && denyOpen) || (!deny && allowOpen)
		}
	}
	if e.steps == nil {
		e.steps = []investigation.Step{}
	}
	return v
}

// combine is the verdict table of spec section 4.7.
func combine(principalGap, D, Du, M, A, Au bool) investigation.Verdict {
	switch {
	case principalGap:
		return investigation.Unknown
	case D:
		return investigation.DeniedExplicit
	case Du || M:
		return investigation.Unknown
	case A:
		return investigation.Allowed
	case Au:
		return investigation.Unknown
	default:
		return investigation.DeniedImplicit
	}
}

// outOfScopeGaps lists the AWS layers CW-001 never evaluates. They cannot
// change the scoped verdict. Observed facts are added; nothing is guessed.
func outOfScopeGaps(q Question, principalAccount, boundary string) []investigation.Gap {
	resourcePolicy := "Resource-based policies are not evaluated in CW-001."
	// Only a 12-digit account ID counts; AWS-managed resources use "aws".
	if acct := arnField(q.Resource, 4); q.Resource != "*" && isAccountID(acct) && principalAccount != "" && acct != principalAccount {
		resourcePolicy += fmt.Sprintf(" The resource account (%s) differs from the principal account (%s); cross-account access also requires the resource owner's policy.", acct, principalAccount)
	}
	boundaryDetail := "Permissions boundaries are not evaluated in CW-001."
	if boundary != "" {
		boundaryDetail += fmt.Sprintf(" The principal has a permissions boundary attached: %s.", boundary)
	}
	mk := func(layer, detail string) investigation.Gap {
		return investigation.Gap{Layer: layer, Reason: investigation.OutOfScope, Code: LayerNotInCW001, Detail: detail}
	}
	return []investigation.Gap{
		mk("aws.resource_policy", resourcePolicy),
		mk("aws.permissions_boundary", boundaryDetail),
		mk("aws.scp", "Service control policies are not evaluated in CW-001."),
		mk("aws.rcp", "Resource control policies are not evaluated in CW-001."),
		mk("aws.session_policy", "Session policies are not evaluated in CW-001."),
	}
}

// arnField returns field i of an ARN, or "" if the ARN has fewer fields.
func arnField(arn string, i int) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return ""
	}
	return parts[i]
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func quoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func formatVars(vars []string) string {
	f := make([]string, len(vars))
	for i, v := range vars {
		f[i] = "${" + v + "}"
	}
	return strings.Join(f, ", ")
}

// IsInputError reports whether err is an input error.
func IsInputError(err error) bool {
	var ie *InputError
	return errors.As(err, &ie)
}
