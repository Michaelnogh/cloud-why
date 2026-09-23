# cloud-why

cloud-why is the Cloud Authorization Intelligence project of [Infrastructure Lab](https://github.com/Michaelnogh/infrastructure-lab).

> Explain exactly why a principal can or cannot perform an action against a resource.

## Status

**Implementation has not started.** This repository contains no application code yet. It will contain the cloud-why implementation.

The roadmap, architecture decisions and specifications live in Infrastructure Lab:

- Project definition: [projects/cloud-why/PROJECT.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/PROJECT.md)
- Roadmap: [projects/cloud-why/ROADMAP.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/ROADMAP.md)
- Status: [projects/cloud-why/STATUS.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/projects/cloud-why/STATUS.md)
- Architecture: [ARCHITECTURE.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/ARCHITECTURE.md)
- Decisions: [DECISIONS.md](https://github.com/Michaelnogh/infrastructure-lab/blob/main/DECISIONS.md)

## What cloud-why will do

- **One access decision at a time.** For a question (principal, action, resource, context), cloud-why returns a verdict, the ordered evidence that produced it, what it could not evaluate, and where its data came from.
- **Offline-first.** Evaluation runs from a local snapshot file with no credentials, no network and no cloud account. Collecting a snapshot is a separate, read-only step.
- **Provider semantics stay provider-specific.** Each provider has its own evaluation engine. What is shared is the result shape (Question, Verdict, Evidence, Gaps, Provenance), not a common policy model.
- **No guessing.** Anything it cannot evaluate is reported, and the verdict becomes `UNKNOWN` when that could change the answer.
- **Opt-in provider verification.** Contacting a provider API to cross-check a result will require an explicit flag and will be disclosed before any request.

## Providers

1. AWS (first)
2. Kubernetes
3. GCP
4. Azure

## Planned commands

Nothing below exists yet.

```text
cloud-why explain   --snapshot <file> --principal <id> --action <action> --resource <id>
cloud-why collect   aws --out <file>
cloud-why diff      --plan plan.json --snapshot <file>
```

## Security

- Read-only. No write permissions to any provider.
- No credential storage, no telemetry.
- Network only for collection and opt-in verification.

## License

[Apache-2.0](LICENSE)
