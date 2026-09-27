# cloud-why

cloud-why is the Cloud Authorization Intelligence project of [Infrastructure Lab](https://github.com/Michaelnogh/infrastructure-lab).

> Explain exactly why a principal can or cannot perform an action against a resource.

## Status

Milestone **CW-001** (offline AWS identity-policy explanation) is implemented and tested. There is no release yet.

Providers: AWS first; Kubernetes, GCP and Azure are planned. Each provider keeps its own evaluation semantics; only the result shape (Question, Verdict, Evidence, Gaps, Provenance) is shared.

Roadmap, architecture decisions and specifications live in Infrastructure Lab:

- CW-001 specification: [projects/cloud-why/spec/cw-001-offline-aws-identity-explain.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/spec/cw-001-offline-aws-identity-explain.md)
- Project definition: [projects/cloud-why/PROJECT.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/PROJECT.md)
- Roadmap: [projects/cloud-why/ROADMAP.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/ROADMAP.md)
- Architecture: [ARCHITECTURE.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/ARCHITECTURE.md)

## What CW-001 does

It answers one question, offline: do the **identity-based policies** of an IAM user or role allow this action on this resource? It shows every statement it considered, how each matched, what it could not evaluate, and where its data came from.

```text
Evaluation scope: AWS identity-based policies only
```

| Verdict | Meaning | Exit code |
|---|---|---|
| `ALLOWED` | Allowed within the evaluated identity-policy scope. This does **not** guarantee that the real AWS request succeeds: resource policies, permissions boundaries, SCPs, RCPs and session policies were not evaluated. | 0 |
| `DENIED_EXPLICIT` | A fully evaluable identity-policy `Deny` applies. An applicable explicit Deny overrides any Allow, so this deny is decisive for the final AWS decision. | 3 |
| `DENIED_IMPLICIT` | No identity-policy statement allows or denies the request. Layers outside the scope could still grant access. | 4 |
| `UNKNOWN` | Missing or unsupported information could change the result within the scope. The gaps say exactly what. | 5 |
| input error | Invalid question, snapshot or policy document | 2 |
| internal error | Bug | 1 |

## Usage

Build (Go 1.27; standard library only):

```text
go build -o cloud-why ./cmd/cloud-why
```

Produce a snapshot with your own tooling, for example:

```text
aws iam get-account-authorization-details --output json > snapshot.json
```

Explain one question:

```text
cloud-why explain \
  --snapshot snapshot.json \
  --principal arn:aws:iam::111122223333:role/app \
  --action s3:GetObject \
  --resource arn:aws:s3:::example-bucket/reports/q3.csv \
  [--output text|json]
```

- `--resource "*"` is a literal request value for actions without resource-level permissions (for example `s3:ListAllMyBuckets`). It does **not** mean "any resource". Only a policy `"Resource": "*"` matches it.
- Inside a resource ARN, `*` and `?` are ordinary characters of the request.

## Input

A JSON document in the shape of the IAM `GetAccountAuthorizationDetails` response. Policy documents may be JSON objects or RFC 3986 URL-encoded strings (as returned by the API); both are accepted without manual decoding. Only policies reachable from the requested principal are read. Policy documents with duplicate JSON keys, malformed URL encoding or invalid IAM policy syntax are input errors. Files over 64 MiB are rejected.

## Supported

- IAM users and roles; inline policies; attached managed policies (default version only); group inline and managed policies for users.
- `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`; explicit deny overrides allow; implicit deny.
- Action matching: case-insensitive, `*` and `?`.
- Resource matching: case-sensitive; `*` and `?` within ARN segments; a `*` that ends a segment can expand across colons; incomplete ARNs completed with `*`; wildcards in the partition or service field rejected.
- `Version` `2012-10-17` special variables `${*}`, `${?}`, `${$}`; in `2008-10-17` or version-less documents `${...}` is literal text.

## Not evaluated (reported as gaps)

- `Condition` elements (any statement with one is `NOT_EVALUATED`).
- Policy variables that need request context, such as `${aws:username}`. A resource pattern containing one is always treated as unresolvable, even when its literal part could never match; this conservative behavior is a known follow-up (M1).
- Principals other than IAM users and roles (for example assumed-role sessions).
- Resource-based policies, permissions boundaries, SCPs, RCPs, session policies.
- Whether the action exists or the resource type fits the action (no Service Authorization Reference). Wildcards in the resource-type part of an ARN, which AWS forbids, are not detected.

## Security

- Offline: no credentials, no network, no AWS SDK, no cloud account. The evaluation packages import no file, network or process packages; tests enforce this.
- Read-only. No telemetry. Writes only to stdout and stderr.
- The snapshot is sensitive; keep it private.

## Development

```text
go vet ./...
go test ./...
go test ./cmd/cloud-why -run TestGolden -update   # regenerate golden files, then review them
```

## License

[Apache-2.0](LICENSE)
