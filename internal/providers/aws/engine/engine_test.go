package engine

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Michaelnogh/cloud-why/internal/investigation"
	"github.com/Michaelnogh/cloud-why/internal/providers/aws/snapshot"
)

// Fixtures below follow the GetAccountAuthorizationDetails response shape and
// policy examples from the IAM User Guide.

const (
	acct    = "111122223333"
	roleARN = "arn:aws:iam::111122223333:role/app"
	userARN = "arn:aws:iam::111122223333:user/alice"
	objARN  = "arn:aws:s3:::example-bucket/reports/q3.csv"
)

func st(effect, actionKey, action, resourceKey, resource string, extra ...string) string {
	s := fmt.Sprintf(`{"Effect":%q,%q:%s,%q:%s`, effect, actionKey, jsonValue(action), resourceKey, jsonValue(resource))
	for _, e := range extra {
		s += "," + e
	}
	return s + "}"
}

// jsonValue renders "a|b" as a JSON array and "a" as a JSON string.
func jsonValue(v string) string {
	if strings.Contains(v, "|") {
		b, _ := json.Marshal(strings.Split(v, "|"))
		return string(b)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func allow(action, resource string, extra ...string) string {
	return st("Allow", "Action", action, "Resource", resource, extra...)
}

func deny(action, resource string, extra ...string) string {
	return st("Deny", "Action", action, "Resource", resource, extra...)
}

func doc(stmts ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(stmts, ",") + `]}`
}

func inline(name, document string) string {
	return fmt.Sprintf(`{"PolicyName":%q,"PolicyDocument":%s}`, name, document)
}

// roleSnap is a snapshot with role "app" holding the given inline policy documents.
func roleSnap(docs ...string) string {
	var ps []string
	for i, d := range docs {
		ps = append(ps, inline(fmt.Sprintf("p%d", i), d))
	}
	return fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RoleName":"app","RolePolicyList":[%s],"AttachedManagedPolicies":[]}]}`,
		roleARN, strings.Join(ps, ","))
}

type scenario struct {
	id       string
	snap     string
	q        Question
	verdict  investigation.Verdict
	check    func(t *testing.T, r investigation.Result)
	wantGaps []string // in-scope gap codes, in order
}

func q(action, resource string) Question {
	return Question{Principal: roleARN, Action: action, Resource: resource}
}

func explain(t *testing.T, snap string, question Question) investigation.Result {
	t.Helper()
	s, err := snapshot.Parse([]byte(snap))
	if err != nil {
		t.Fatalf("snapshot.Parse: %v", err)
	}
	r, err := Explain(s, question, investigation.InputProvenance{Path: "fixture", SHA256: "0"}, "test")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	return r
}

func reasonsOf(r investigation.Result, step int) []string { return r.Evidence[step-1].Reasons }

func hasReason(r investigation.Result, step int, reason string) bool {
	return slices.Contains(reasonsOf(r, step), reason)
}

func gap(r investigation.Result, code string) *investigation.Gap {
	for i := range r.Gaps {
		if r.Gaps[i].Code == code {
			return &r.Gaps[i]
		}
	}
	return nil
}

func inScopeCodes(r investigation.Result) []string {
	var codes []string
	for _, g := range r.Gaps {
		if g.Reason != investigation.OutOfScope {
			codes = append(codes, g.Code)
		}
	}
	return codes
}

func decisiveSteps(r investigation.Result) []int {
	var d []int
	for _, s := range r.Evidence {
		if s.Decisive {
			d = append(d, s.Step)
		}
	}
	return d
}

func expectReason(step int, reason string) func(t *testing.T, r investigation.Result) {
	return func(t *testing.T, r investigation.Result) {
		t.Helper()
		if !hasReason(r, step, reason) {
			t.Errorf("step %d reasons %v, want %s", step, reasonsOf(r, step), reason)
		}
	}
}

func all(checks ...func(t *testing.T, r investigation.Result)) func(t *testing.T, r investigation.Result) {
	return func(t *testing.T, r investigation.Result) {
		t.Helper()
		for _, c := range checks {
			c(t, r)
		}
	}
}

func expectDecisive(steps ...int) func(t *testing.T, r investigation.Result) {
	return func(t *testing.T, r investigation.Result) {
		t.Helper()
		if got := decisiveSteps(r); !slices.Equal(got, steps) {
			t.Errorf("decisive steps %v, want %v", got, steps)
		}
	}
}

func expectAffects(code string, want bool) func(t *testing.T, r investigation.Result) {
	return func(t *testing.T, r investigation.Result) {
		t.Helper()
		g := gap(r, code)
		if g == nil {
			t.Fatalf("no gap %s", code)
		}
		if g.AffectsVerdict != want {
			t.Errorf("gap %s affects_verdict = %v, want %v", code, g.AffectsVerdict, want)
		}
	}
}

func expectGapDetail(layer, substr string) func(t *testing.T, r investigation.Result) {
	return func(t *testing.T, r investigation.Result) {
		t.Helper()
		for _, g := range r.Gaps {
			if g.Layer == layer {
				if !strings.Contains(g.Detail, substr) {
					t.Errorf("gap %s detail %q, want containing %q", layer, g.Detail, substr)
				}
				return
			}
		}
		t.Errorf("no gap for layer %s", layer)
	}
}

// userSnap: alice with inline policy, a managed policy, and group "developers".
const userSnap = `{
 "UserDetailList":[{"Arn":"arn:aws:iam::111122223333:user/alice","UserName":"alice",
   "UserPolicyList":[{"PolicyName":"user-inline","PolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}}],
   "AttachedManagedPolicies":[{"PolicyName":"user-managed","PolicyArn":"arn:aws:iam::111122223333:policy/user-managed"}],
   "GroupList":["developers"]}],
 "GroupDetailList":[{"Arn":"arn:aws:iam::111122223333:group/developers","GroupName":"developers",
   "GroupPolicyList":[],
   "AttachedManagedPolicies":[{"PolicyName":"S3-read-only-specific-bucket","PolicyArn":"arn:aws:iam::111122223333:policy/S3-read-only-specific-bucket"}]}],
 "Policies":[
  {"Arn":"arn:aws:iam::111122223333:policy/user-managed","PolicyName":"user-managed","DefaultVersionId":"v1",
   "PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}}]},
  {"Arn":"arn:aws:iam::111122223333:policy/S3-read-only-specific-bucket","PolicyName":"S3-read-only-specific-bucket","DefaultVersionId":"v1",
   "PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":["arn:aws:s3:::example-bucket","arn:aws:s3:::example-bucket/*"]}]}}]}
 ]}`

// payroll is the AWS NotResource example policy, plus an s3:* allow.
var payroll = roleSnap(doc(
	`{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::HRBucket/Payroll","arn:aws:s3:::HRBucket/Payroll/*"]}`,
	allow("s3:*", "*"),
))

func scenarios() []scenario {
	return []scenario{
		{id: "S01 exact allow", snap: roleSnap(doc(allow("s3:GetObject", objARN))), q: q("s3:GetObject", objARN),
			verdict: investigation.Allowed, check: all(expectDecisive(1), expectReason(1, ActionMatched), expectReason(1, ResourceMatched), expectReason(1, ConditionAbsent))},
		{id: "S02 allow via s3:Get*", snap: roleSnap(doc(allow("s3:Get*", "arn:aws:s3:::example-bucket/*"))), q: q("s3:GetObject", objARN),
			verdict: investigation.Allowed},
		{id: "S03 action case differs", snap: roleSnap(doc(allow("S3:getobject", objARN))), q: q("s3:GetObject", objARN),
			verdict: investigation.Allowed},
		{id: "S04 non-matching action", snap: roleSnap(doc(allow("s3:PutObject", objARN))), q: q("s3:GetObject", objARN),
			verdict: investigation.DeniedImplicit, check: all(expectReason(1, ActionNotMatched), expectReason(1, ResourceNotChecked), expectReason(1, ConditionNotChecked), expectDecisive())},
		{id: "S05 non-matching resource", snap: roleSnap(doc(allow("s3:GetObject", "arn:aws:s3:::other-bucket/*"))), q: q("s3:GetObject", objARN),
			verdict: investigation.DeniedImplicit, check: expectReason(1, ResourceNotMatched)},
		{id: "S06 resource differs only in case", snap: roleSnap(doc(allow("s3:GetObject", "arn:aws:s3:::example-bucket/Reports/q3.csv"))), q: q("s3:GetObject", objARN),
			verdict: investigation.DeniedImplicit},
		{id: "S07 allow and deny in the same policy", snap: roleSnap(doc(allow("s3:GetObject", "*"), deny("s3:GetObject", "arn:aws:s3:::example-bucket/*"))), q: q("s3:GetObject", objARN),
			verdict: investigation.DeniedExplicit, check: func(t *testing.T, r investigation.Result) {
				expectDecisive(2)(t, r)
				if !slices.Contains(r.Evidence[1].Explanation, decisiveDenyLine) {
					t.Errorf("decisive deny line missing: %v", r.Evidence[1].Explanation)
				}
			}},
		{id: "S08 inline allow, managed deny",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[%s],"AttachedManagedPolicies":[{"PolicyName":"deny-s3","PolicyArn":"arn:aws:iam::111122223333:policy/deny-s3"}]}],
				"Policies":[{"Arn":"arn:aws:iam::111122223333:policy/deny-s3","PolicyName":"deny-s3","PolicyVersionList":[{"VersionId":"v2","IsDefaultVersion":true,"Document":%s}]}]}`,
				roleARN, inline("p0", doc(allow("s3:*", "*"))), doc(deny("s3:GetObject", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedExplicit, check: func(t *testing.T, r investigation.Result) {
				expectDecisive(2)(t, r)
				if s := r.Evidence[1].Source; s.Kind != "aws.role_managed_policy" || s.Version != "v2" || s.ID != "arn:aws:iam::111122223333:policy/deny-s3" {
					t.Errorf("managed source = %+v", s)
				}
			}},
		{id: "S09 third statement applies", snap: roleSnap(doc(allow("s3:PutObject", "*"), allow("s3:GetObject", "arn:aws:s3:::other/*"), allow("s3:GetObject", "arn:aws:s3:::example-bucket/*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed, check: expectDecisive(3)},
		{id: "S10 allowed via group managed policy", snap: userSnap, q: Question{Principal: userARN, Action: "s3:GetObject", Resource: objARN},
			verdict: investigation.Allowed, check: func(t *testing.T, r investigation.Result) {
				expectDecisive(3)(t, r)
				s := r.Evidence[2].Source
				if s.Kind != "aws.group_managed_policy" || s.Via != "arn:aws:iam::111122223333:group/developers" || s.Version != "v1" {
					t.Errorf("group source = %+v", s)
				}
				if r.Evidence[0].Source.Kind != "aws.user_inline_policy" || r.Evidence[1].Source.Kind != "aws.user_managed_policy" {
					t.Errorf("policy order wrong")
				}
			}},
		{id: "S11 group inline deny overrides user inline allow",
			snap: fmt.Sprintf(`{"UserDetailList":[{"Arn":%q,"UserPolicyList":[%s],"GroupList":["g"]}],"GroupDetailList":[{"Arn":"arn:aws:iam::111122223333:group/g","GroupName":"g","GroupPolicyList":[%s]}]}`,
				userARN, inline("u", doc(allow("s3:*", "*"))), inline("gdeny", doc(deny("s3:GetObject", "*")))),
			q: Question{Principal: userARN, Action: "s3:GetObject", Resource: objARN}, verdict: investigation.DeniedExplicit,
			check: func(t *testing.T, r investigation.Result) {
				if r.Evidence[1].Source.Kind != "aws.group_inline_policy" || !r.Evidence[1].Decisive {
					t.Errorf("group inline deny not decisive: %+v", r.Evidence[1])
				}
			}},
		{id: "S12 NotAction iam:* allows s3", snap: roleSnap(doc(st("Allow", "NotAction", "iam:*", "Resource", "*"))), q: q("s3:GetObject", objARN),
			verdict: investigation.Allowed, check: expectReason(1, NotActionNotExcluded)},
		{id: "S13 NotAction iam:* does not cover iam", snap: roleSnap(doc(st("Allow", "NotAction", "iam:*", "Resource", "*"))),
			q: q("iam:CreateUser", "arn:aws:iam::111122223333:user/bob"), verdict: investigation.DeniedImplicit, check: expectReason(1, NotActionExcluded)},
		{id: "S14 NotAction scoped by Resource (AWS example)", snap: roleSnap(doc(st("Allow", "NotAction", "s3:DeleteBucket", "Resource", "arn:aws:s3:::*"))),
			q: q("ec2:RunInstances", "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"), verdict: investigation.DeniedImplicit,
			check: all(expectReason(1, NotActionNotExcluded), expectReason(1, ResourceNotMatched))},
		{id: "S15 Deny NotAction does not deny the listed action",
			snap: roleSnap(doc(st("Deny", "NotAction", "iam:*", "Resource", "*"), allow("*", "*"))),
			q:    q("iam:ListUsers", "arn:aws:iam::111122223333:user/bob"), verdict: investigation.Allowed,
			check: all(expectReason(1, NotActionExcluded), expectDecisive(2))},
		{id: "S16 NotResource deny (AWS payroll example), other bucket", snap: payroll,
			q: q("s3:GetObject", "arn:aws:s3:::OtherBucket/x"), verdict: investigation.DeniedExplicit, check: expectReason(1, NotResourceNotExcluded)},
		{id: "S17 NotResource deny excludes payroll", snap: payroll,
			q: q("s3:GetObject", "arn:aws:s3:::HRBucket/Payroll/x"), verdict: investigation.Allowed, check: expectReason(1, NotResourceExcluded)},
		{id: "S18 allow Resource *", snap: roleSnap(doc(allow("s3:GetObject", "*"))), q: q("s3:GetObject", objARN), verdict: investigation.Allowed},
		{id: "S18a request * with policy *", snap: roleSnap(doc(allow("s3:ListAllMyBuckets", "*"))), q: q("s3:ListAllMyBuckets", "*"), verdict: investigation.Allowed},
		{id: "S18b request * with ARN pattern", snap: roleSnap(doc(allow("s3:ListAllMyBuckets", "arn:aws:s3:::*"))), q: q("s3:ListAllMyBuckets", "*"),
			verdict: investigation.DeniedImplicit, check: expectReason(1, ResourceNotMatched)},
		{id: "S18c request * not excluded by ARN NotResource",
			snap: roleSnap(doc(st("Deny", "Action", "s3:ListAllMyBuckets", "NotResource", "arn:aws:s3:::secret/*"), allow("*", "*"))),
			q:    q("s3:ListAllMyBuckets", "*"), verdict: investigation.DeniedExplicit},
		{id: "S18d request * excluded by NotResource *",
			snap: roleSnap(doc(st("Deny", "Action", "s3:ListAllMyBuckets", "NotResource", "*"), allow("*", "*"))),
			q:    q("s3:ListAllMyBuckets", "*"), verdict: investigation.Allowed, check: expectReason(1, NotResourceExcluded)},
		{id: "S19 trailing * crosses colons", snap: roleSnap(doc(allow("logs:PutLogEvents", "arn:aws:logs:*:111122223333:log-group:app-*"))),
			q: q("logs:PutLogEvents", "arn:aws:logs:us-east-1:111122223333:log-group:app-web:log-stream:1"), verdict: investigation.Allowed},
		{id: "S20 mid-segment * does not cross a colon", snap: roleSnap(doc(allow("logs:PutLogEvents", "arn:aws:logs:us-east-1:111122223333:log-group:app*web"))),
			q: q("logs:PutLogEvents", "arn:aws:logs:us-east-1:111122223333:log-group:app:web"), verdict: investigation.DeniedImplicit},
		{id: "S21 incomplete ARN arn:aws:sqs", snap: roleSnap(doc(allow("sqs:SendMessage", "arn:aws:sqs"))),
			q: q("sqs:SendMessage", "arn:aws:sqs:us-east-1:111122223333:queue1"), verdict: investigation.Allowed},
		{id: "S22 only applicable allow is conditional", snap: roleSnap(doc(allow("s3:GetObject", "*", `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ConditionNotEvaluated},
			check: all(expectAffects(ConditionNotEvaluated, true), expectDecisive(1))},
		{id: "S23 allow plus conditional deny", snap: roleSnap(doc(allow("s3:GetObject", "*"), deny("s3:*", "*", `"Condition":{"Bool":{"aws:SecureTransport":"false"}}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ConditionNotEvaluated},
			check: all(expectAffects(ConditionNotEvaluated, true), expectDecisive(2))},
		{id: "S24 deny plus conditional allow", snap: roleSnap(doc(deny("s3:GetObject", "*"), allow("s3:*", "*", `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedExplicit, wantGaps: []string{ConditionNotEvaluated},
			check: expectAffects(ConditionNotEvaluated, false)},
		{id: "S25 allow plus conditional allow", snap: roleSnap(doc(allow("s3:GetObject", "*"), allow("s3:*", "*", `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed, wantGaps: []string{ConditionNotEvaluated},
			check: all(expectAffects(ConditionNotEvaluated, false), expectDecisive(1))},
		{id: "S26 empty Condition is present", snap: roleSnap(doc(allow("s3:GetObject", "*", `"Condition":{}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ConditionNotEvaluated}},
		{id: "S27 condition on a non-matching statement", snap: roleSnap(doc(allow("s3:PutObject", "*", `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedImplicit, check: expectReason(1, ConditionNotChecked)},
		{id: "S28 2012 policy variable", snap: roleSnap(doc(allow("s3:GetObject", "arn:aws:s3:::example-bucket/${aws:username}/*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{PolicyVariableUnresolved},
			check: expectAffects(PolicyVariableUnresolved, true)},
		{id: "S29 2008 variable is literal",
			snap: roleSnap(`{"Version":"2008-10-17","Statement":[` + allow("s3:GetObject", "arn:aws:s3:::example-bucket/${aws:username}/*") + `]}`),
			q:    q("s3:GetObject", objARN), verdict: investigation.DeniedImplicit},
		{id: "S29b 2008 variable matched literally",
			snap: roleSnap(`{"Version":"2008-10-17","Statement":[` + allow("s3:GetObject", "arn:aws:s3:::example-bucket/${aws:username}/*") + `]}`),
			q:    q("s3:GetObject", "arn:aws:s3:::example-bucket/${aws:username}/x"), verdict: investigation.Allowed},
		{id: "S30 variable pattern next to matching literal", snap: roleSnap(doc(allow("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*|arn:aws:s3:::example-bucket/*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed},
		{id: "S31 managed policy missing",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"gone","PolicyArn":"arn:aws:iam::aws:policy/Gone"}]}]}`, roleARN),
			q:    q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ManagedPolicyMissing}, check: expectAffects(ManagedPolicyMissing, true)},
		{id: "S32 missing managed policy plus deny",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[%s],"AttachedManagedPolicies":[{"PolicyName":"gone","PolicyArn":"arn:aws:iam::aws:policy/Gone"}]}]}`, roleARN, inline("d", doc(deny("s3:*", "*")))),
			q:    q("s3:GetObject", objARN), verdict: investigation.DeniedExplicit, wantGaps: []string{ManagedPolicyMissing}, check: expectAffects(ManagedPolicyMissing, false)},
		{id: "S33 group missing",
			snap: fmt.Sprintf(`{"UserDetailList":[{"Arn":%q,"UserPolicyList":[%s],"GroupList":["ghost"]}]}`, userARN, inline("u", doc(allow("s3:*", "*")))),
			q:    Question{Principal: userARN, Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Unknown, wantGaps: []string{GroupMissing}},
		{id: "S34 principal not in snapshot", snap: roleSnap(doc(allow("*", "*"))),
			q:       Question{Principal: "arn:aws:iam::111122223333:role/other", Action: "s3:GetObject", Resource: objARN},
			verdict: investigation.Unknown, wantGaps: []string{PrincipalNotInSnapshot},
			check: func(t *testing.T, r investigation.Result) {
				if len(r.Evidence) != 0 {
					t.Errorf("evidence = %v, want none", r.Evidence)
				}
			}},
		{id: "S35 assumed-role principal", snap: roleSnap(doc(allow("*", "*"))),
			q:       Question{Principal: "arn:aws:sts::111122223333:assumed-role/app/session", Action: "s3:GetObject", Resource: objARN},
			verdict: investigation.Unknown, wantGaps: []string{PrincipalTypeNotSupported}},
		{id: "S36 permissions boundary reported",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[%s],"PermissionsBoundary":{"PermissionsBoundaryType":"Policy","PermissionsBoundaryArn":"arn:aws:iam::111122223333:policy/boundary"}}]}`, roleARN, inline("p", doc(allow("s3:*", "*")))),
			q:    q("s3:GetObject", objARN), verdict: investigation.Allowed,
			check: expectGapDetail("aws.permissions_boundary", "arn:aws:iam::111122223333:policy/boundary")},
		{id: "S37 cross-account resource", snap: roleSnap(doc(allow("sqs:SendMessage", "*"))),
			q: q("sqs:SendMessage", "arn:aws:sqs:us-east-1:444455556666:queue1"), verdict: investigation.Allowed,
			check: expectGapDetail("aws.resource_policy", "differs from the principal account")},
		{id: "S38 no policies", snap: roleSnap(), q: q("s3:GetObject", objARN), verdict: investigation.DeniedImplicit,
			check: func(t *testing.T, r investigation.Result) {
				if len(r.Evidence) != 0 {
					t.Errorf("evidence = %v", r.Evidence)
				}
			}},
		{id: "S39 truncated snapshot with missing managed policy",
			snap: fmt.Sprintf(`{"IsTruncated":true,"RoleDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"x","PolicyArn":"arn:aws:iam::111122223333:policy/x"}]}]}`, roleARN),
			q:    q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ManagedPolicyMissing},
			check: func(t *testing.T, r investigation.Result) {
				if !strings.Contains(gap(r, ManagedPolicyMissing).Detail, "truncated") || !r.Provenance.Input.IsTruncated {
					t.Errorf("truncation not reported")
				}
			}},
		{id: "S40 non-default version ignored",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::111122223333:policy/m"}]}],
				"Policies":[{"Arn":"arn:aws:iam::111122223333:policy/m","PolicyName":"m","DefaultVersionId":"v1","PolicyVersionList":[
				{"VersionId":"v2","IsDefaultVersion":false,"Document":%s},
				{"VersionId":"v1","IsDefaultVersion":true,"Document":%s}]}]}`, roleARN, doc(deny("*", "*")), doc(allow("s3:GetObject", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed,
			check: func(t *testing.T, r investigation.Result) {
				if len(r.Evidence) != 1 || r.Evidence[0].Source.Version != "v1" {
					t.Errorf("evidence = %+v", r.Evidence)
				}
			}},
		{id: "S40b no default version",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::111122223333:policy/m"}]}],
				"Policies":[{"Arn":"arn:aws:iam::111122223333:policy/m","PolicyName":"m","PolicyVersionList":[{"VersionId":"v2","IsDefaultVersion":false,"Document":%s}]}]}`, roleARN, doc(allow("*", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{DefaultVersionMissing}},
		{id: "S42 broken policy on an unrelated principal",
			snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[%s]},{"Arn":"arn:aws:iam::111122223333:role/other","RolePolicyList":[{"PolicyName":"bad","PolicyDocument":"%%zz"}]}]}`,
				roleARN, inline("p", doc(allow("s3:*", "*")))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed},
	}
}

func TestScenarios(t *testing.T) {
	for _, sc := range scenarios() {
		t.Run(sc.id, func(t *testing.T) {
			r := explain(t, sc.snap, sc.q)
			if r.Verdict != sc.verdict {
				t.Fatalf("verdict %s, want %s\n%s", r.Verdict, sc.verdict, mustJSON(r))
			}
			if got := inScopeCodes(r); !slices.Equal(got, sc.wantGaps) {
				t.Errorf("in-scope gaps %v, want %v", got, sc.wantGaps)
			}
			if sc.check != nil {
				sc.check(t, r)
			}
			checkInvariants(t, r)
		})
	}
}

// checkInvariants covers P03, P04 and P05.
func checkInvariants(t *testing.T, r investigation.Result) {
	t.Helper()
	switch r.Verdict {
	case investigation.DeniedExplicit:
		ok := false
		for _, s := range r.Evidence {
			if s.Decisive && s.Outcome == investigation.Matched && s.Effect == investigation.EffectDeny && slices.Contains(s.Explanation, decisiveDenyLine) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("P03: DENIED_EXPLICIT without decisive matched Deny")
		}
	case investigation.Allowed:
		ok := false
		for _, s := range r.Evidence {
			if s.Decisive && s.Outcome == investigation.Matched && s.Effect == investigation.EffectAllow {
				ok = true
			}
		}
		if !ok {
			t.Errorf("P03: ALLOWED without decisive matched Allow")
		}
	case investigation.Unknown:
		ok := false
		for _, g := range r.Gaps {
			if g.AffectsVerdict {
				ok = true
			}
		}
		if !ok {
			t.Errorf("P04: UNKNOWN without an affecting gap")
		}
	}
	var out []string
	for _, g := range r.Gaps {
		if g.Reason == investigation.OutOfScope {
			out = append(out, g.Layer)
			if g.AffectsVerdict {
				t.Errorf("P05: out-of-scope gap %s affects verdict", g.Layer)
			}
		}
	}
	want := []string{"aws.resource_policy", "aws.permissions_boundary", "aws.scp", "aws.rcp", "aws.session_policy"}
	if !slices.Equal(out, want) {
		t.Errorf("P05: out-of-scope layers %v, want %v", out, want)
	}
	if r.Question.Scope.Label != "AWS identity-based policies only" || !slices.Equal(r.Question.Scope.Layers, []string{"aws.identity"}) {
		t.Errorf("P05: scope = %+v", r.Question.Scope)
	}
	if r.Provenance.ProviderContacted || r.Provenance.NetworkUsed || r.Provenance.CollectedAt != nil {
		t.Errorf("provenance claims contact, network or collection time: %+v", r.Provenance)
	}
}

// P01 at engine level: identical input gives byte-identical output.
func TestDeterministic(t *testing.T) {
	for _, sc := range scenarios() {
		a := mustJSON(explain(t, sc.snap, sc.q))
		b := mustJSON(explain(t, sc.snap, sc.q))
		if a != b {
			t.Errorf("%s: output differs between runs", sc.id)
		}
	}
}

// P02: statement and policy order never changes the verdict.
func TestOrderIndependence(t *testing.T) {
	for _, sc := range scenarios() {
		reversed := transform(t, sc.snap, reverseLists)
		r := explain(t, reversed, sc.q)
		if r.Verdict != sc.verdict {
			t.Errorf("%s: reversed verdict %s, want %s", sc.id, r.Verdict, sc.verdict)
		}
	}
}

// P08 and S41: URL-encoded documents give the same result as plain JSON,
// apart from the recorded document encoding.
func TestEncodingEquivalence(t *testing.T) {
	for _, sc := range scenarios() {
		encoded := transform(t, sc.snap, encodeDocuments)
		if encoded == sc.snap {
			continue
		}
		plain := mustJSON(explain(t, sc.snap, sc.q))
		enc := mustJSON(explain(t, encoded, sc.q))
		enc = strings.ReplaceAll(enc, `"document_encoding": "url-encoded"`, `"document_encoding": "json-object"`)
		if plain != enc {
			t.Errorf("%s: encoded result differs from plain result", sc.id)
		}
	}
}

// U8: the verdict table of spec section 4.7.
func TestCombine(t *testing.T) {
	for i := 0; i < 64; i++ {
		p, D, Du, M, A, Au := i&1 != 0, i&2 != 0, i&4 != 0, i&8 != 0, i&16 != 0, i&32 != 0
		var want investigation.Verdict
		if p {
			want = investigation.Unknown
		} else if D {
			want = investigation.DeniedExplicit
		} else if Du || M {
			want = investigation.Unknown
		} else if A {
			want = investigation.Allowed
		} else if Au {
			want = investigation.Unknown
		} else {
			want = investigation.DeniedImplicit
		}
		if got := combine(p, D, Du, M, A, Au); got != want {
			t.Errorf("combine(p=%v D=%v Du=%v M=%v A=%v Au=%v) = %s, want %s", p, D, Du, M, A, Au, got, want)
		}
	}
}

func TestInputErrors(t *testing.T) {
	bad := func(docJSON string) string { return roleSnap(docJSON) }
	tests := []struct {
		name string
		snap string
		q    Question
		want string
	}{
		{"E03 malformed URL encoding", fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[{"PolicyName":"p","PolicyDocument":"%%zz"}]}]}`, roleARN), q("s3:GetObject", objARN), "malformed URL encoding"},
		{"E04 decoded text not JSON", fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[{"PolicyName":"p","PolicyDocument":"hello"}]}]}`, roleARN), q("s3:GetObject", objARN), "not a JSON object"},
		{"E05 decoded JSON not an IAM policy", fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"RolePolicyList":[{"PolicyName":"p","PolicyDocument":"%%7B%%22Statement%%22%%3A%%7B%%22Effect%%22%%3A%%22allow%%22%%7D%%7D"}]}]}`, roleARN), q("s3:GetObject", objARN), "invalid IAM policy"},
		{"E10 wildcard in service field", bad(doc(allow("*", "arn:aws:s*:::x"))), q("s3:GetObject", objARN), "partition or service"},
		{"managed default version invalid", fmt.Sprintf(`{"RoleDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::1:policy/m"}]}],"Policies":[{"Arn":"arn:aws:iam::1:policy/m","PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":"%%7B"}]}]}`, roleARN), q("s3:GetObject", objARN), "not a JSON object"},
		{"E12 wildcard action", roleSnap(), q("s3:Get*", objARN), "action must be"},
		{"E13 resource with fewer than six fields", roleSnap(), q("s3:GetObject", "arn:aws:s3"), "resource must be"},
		{"principal not an ARN", roleSnap(), Question{Principal: "app", Action: "s3:GetObject", Resource: objARN}, "principal must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := snapshot.Parse([]byte(tt.snap))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Explain(s, tt.q, investigation.InputProvenance{}, "test")
			if err == nil || !IsInputError(err) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want input error containing %q", err, tt.want)
			}
		})
	}
}

func mustJSON(r investigation.Result) string {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// transform rewrites a snapshot through a generic JSON walk.
func transform(t *testing.T, snap string, f func(key string, v any) any) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(snap), &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(walk("", v, f))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); s != compact(t, snap) {
		return s
	}
	return snap
}

func compact(t *testing.T, s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func walk(key string, v any, f func(string, any) any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			x[k] = walk(k, c, f)
		}
	case []any:
		for i, c := range x {
			x[i] = walk(key, c, f)
		}
	}
	return f(key, v)
}

var reversible = map[string]bool{
	"Statement": true, "UserPolicyList": true, "RolePolicyList": true, "GroupPolicyList": true,
	"AttachedManagedPolicies": true, "GroupList": true, "Action": true, "Resource": true, "NotResource": true,
}

func reverseLists(key string, v any) any {
	if l, ok := v.([]any); ok && reversible[key] {
		slices.Reverse(l)
	}
	return v
}

// encodeDocuments replaces policy document objects with RFC 3986
// percent-encoded strings, as GetAccountAuthorizationDetails returns them.
func encodeDocuments(key string, v any) any {
	if key != "PolicyDocument" && key != "Document" {
		return v
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	b, _ := json.Marshal(m)
	return percentEncode(string(b))
}

func percentEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Review regression tests (2026-09-23).
func TestReviewRegressions(t *testing.T) {
	cond := `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`
	tests := []scenario{
		// NotAction: wildcard exclusion is case-insensitive, like Action.
		{id: "R01 NotAction wildcard excludes, case-insensitive", snap: roleSnap(doc(st("Allow", "NotAction", "S3:get*", "Resource", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedImplicit, check: expectReason(1, NotActionExcluded)},
		// NotAction: any listed pattern excludes.
		{id: "R02 NotAction list, second pattern excludes", snap: roleSnap(doc(st("Allow", "NotAction", "iam:*|s3:GetObject", "Resource", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedImplicit, check: expectReason(1, NotActionExcluded)},
		// NotAction with Deny: unlisted action on a resource outside the Resource scope is not denied.
		{id: "R03 Deny NotAction scoped by Resource", snap: roleSnap(doc(st("Deny", "NotAction", "iam:*", "Resource", "arn:aws:s3:::secret/*"), allow("*", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed, check: all(expectReason(1, NotActionNotExcluded), expectReason(1, ResourceNotMatched))},
		// NotAction with Deny: unlisted action inside the Resource scope is denied.
		{id: "R04 Deny NotAction inside Resource scope", snap: roleSnap(doc(st("Deny", "NotAction", "iam:*", "Resource", "arn:aws:s3:::example-bucket/*"), allow("*", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.DeniedExplicit, check: expectDecisive(1)},
		// NotAction with Condition: applies only if the condition holds, so it is not evaluated.
		{id: "R05 Deny NotAction with Condition", snap: roleSnap(doc(st("Deny", "NotAction", "iam:*", "Resource", "*", cond), allow("*", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Unknown, wantGaps: []string{ConditionNotEvaluated}},
		// NotAction exclusion makes the Condition irrelevant: no gap.
		{id: "R06 excluded NotAction with Condition", snap: roleSnap(doc(st("Deny", "NotAction", "s3:*", "Resource", "*", cond), allow("*", "*"))),
			q: q("s3:GetObject", objARN), verdict: investigation.Allowed},
		// Request "*" (no resource-level permissions) against NotAction with an ARN-scoped Resource.
		{id: "R07 NotAction, request *, ARN Resource", snap: roleSnap(doc(st("Allow", "NotAction", "s3:DeleteBucket", "Resource", "arn:aws:s3:::*"))),
			q: q("s3:ListAllMyBuckets", "*"), verdict: investigation.DeniedImplicit},
		// Managed policy attached directly and through a group: evaluated once per attachment.
		{id: "R08 duplicate attachment",
			snap: fmt.Sprintf(`{"UserDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::111122223333:policy/m"}],"GroupList":["g"]}],
				"GroupDetailList":[{"Arn":"arn:aws:iam::111122223333:group/g","GroupName":"g","AttachedManagedPolicies":[{"PolicyName":"m","PolicyArn":"arn:aws:iam::111122223333:policy/m"}]}],
				"Policies":[{"Arn":"arn:aws:iam::111122223333:policy/m","PolicyName":"m","PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":%s}]}]}`, userARN, doc(allow("s3:*", "*"))),
			q: Question{Principal: userARN, Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Allowed,
			check: func(t *testing.T, r investigation.Result) {
				if len(r.Evidence) != 2 || r.Evidence[0].Source.Via != "" || r.Evidence[1].Source.Via == "" {
					t.Errorf("want one direct and one group step, got %+v", r.Evidence)
				}
			}},
		// Principal ARN with a path must match exactly.
		{id: "R09 role with path", snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":"arn:aws:iam::111122223333:role/service/app","RolePolicyList":[%s]}]}`, inline("p", doc(allow("*", "*")))),
			q: Question{Principal: "arn:aws:iam::111122223333:role/service/app", Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Allowed},
		{id: "R10 role path omitted is a different ARN", snap: fmt.Sprintf(`{"RoleDetailList":[{"Arn":"arn:aws:iam::111122223333:role/service/app","RolePolicyList":[%s]}]}`, inline("p", doc(allow("*", "*")))),
			q: Question{Principal: roleARN, Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Unknown, wantGaps: []string{PrincipalNotInSnapshot}},
		{id: "R11 principal ARN case differs", snap: roleSnap(doc(allow("*", "*"))),
			q: Question{Principal: "arn:aws:iam::111122223333:role/App", Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Unknown, wantGaps: []string{PrincipalNotInSnapshot}},
		{id: "R12 root principal unsupported", snap: roleSnap(doc(allow("*", "*"))),
			q: Question{Principal: "arn:aws:iam::111122223333:root", Action: "s3:GetObject", Resource: objARN}, verdict: investigation.Unknown, wantGaps: []string{PrincipalTypeNotSupported}},
		// AWS-managed resources carry account "aws": not a cross-account request.
		{id: "R13 aws account field is not cross-account", snap: roleSnap(doc(allow("iam:GetPolicy", "*"))),
			q: q("iam:GetPolicy", "arn:aws:iam::aws:policy/AdministratorAccess"), verdict: investigation.Allowed,
			check: func(t *testing.T, r investigation.Result) {
				for _, g := range r.Gaps {
					if strings.Contains(g.Detail, "cross-account") {
						t.Errorf("unexpected cross-account note: %s", g.Detail)
					}
				}
			}},
		// Explicit deny beats allow regardless of which policy type holds it.
		{id: "R14 user managed deny beats group inline allow",
			snap: fmt.Sprintf(`{"UserDetailList":[{"Arn":%q,"AttachedManagedPolicies":[{"PolicyName":"d","PolicyArn":"arn:aws:iam::111122223333:policy/d"}],"GroupList":["g"]}],
				"GroupDetailList":[{"Arn":"arn:aws:iam::111122223333:group/g","GroupName":"g","GroupPolicyList":[%s]}],
				"Policies":[{"Arn":"arn:aws:iam::111122223333:policy/d","PolicyName":"d","PolicyVersionList":[{"VersionId":"v1","IsDefaultVersion":true,"Document":%s}]}]}`,
				userARN, inline("a", doc(allow("*", "*"))), doc(deny("s3:GetObject", "*"))),
			q: Question{Principal: userARN, Action: "s3:GetObject", Resource: objARN}, verdict: investigation.DeniedExplicit, check: expectDecisive(1)},
	}
	for _, sc := range tests {
		t.Run(sc.id, func(t *testing.T) {
			r := explain(t, sc.snap, sc.q)
			if r.Verdict != sc.verdict {
				t.Fatalf("verdict %s, want %s\n%s", r.Verdict, sc.verdict, mustJSON(r))
			}
			if got := inScopeCodes(r); !slices.Equal(got, sc.wantGaps) {
				t.Errorf("in-scope gaps %v, want %v", got, sc.wantGaps)
			}
			if sc.check != nil {
				sc.check(t, r)
			}
			checkInvariants(t, r)
		})
	}
}

func TestMalformedPrincipalARN(t *testing.T) {
	s, _ := snapshot.Parse([]byte(roleSnap()))
	for _, p := range []string{"arn:aws:iam", "arn:", "arn:aws:iam::111122223333"} {
		_, err := Explain(s, Question{Principal: p, Action: "s3:GetObject", Resource: objARN}, investigation.InputProvenance{}, "test")
		if err == nil || !IsInputError(err) {
			t.Errorf("principal %q: error = %v, want input error", p, err)
		}
	}
}
