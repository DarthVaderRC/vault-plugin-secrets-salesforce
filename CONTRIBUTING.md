# Contributing

Thanks for your interest in contributing to **vault-plugin-secrets-salesforce**,
a community HashiCorp Vault secrets engine for Salesforce OAuth tokens.

This is a security-sensitive project. Please read this guide before opening a
pull request.

## Ground rules

- Be respectful and constructive.
- For **security vulnerabilities**, do **not** open a public issue. Follow the
  private disclosure process in [`SECURITY.md`](SECURITY.md).
- Discuss non-trivial changes in an issue before investing significant effort.

## Development workflow

1. **Fork** the repository and create a topic branch off `main`
   (e.g. `feat/short-description` or `fix/short-description`).
2. Make your changes with tests.
3. Ensure all local checks pass (see below).
4. Open a pull request against `main` and fill out the PR template.

### Prerequisites

- Go (see the version pinned in [`go.mod`](go.mod)).
- `make` and, for linting, [`golangci-lint`](https://golangci-lint.run/).

### Common commands

All targets are defined in the [`Makefile`](Makefile):

```sh
make build      # compile the plugin for the host platform
make fmt        # gofmt -w .
make vet        # go vet ./...
make test       # unit tests with the race detector
make cover      # unit tests + coverage summary
make testacc    # acceptance tests (requires VAULT_ACC=1)
```

Run lint the same way CI does:

```sh
golangci-lint run
```

### Before you push

Please make sure the following all succeed locally, since CI enforces them:

- `gofmt` reports no changes (`gofmt -l .` prints nothing)
- `go vet ./...` is clean
- `golangci-lint run` is clean
- `make test` passes (race detector)
- `make testacc` passes where applicable (`VAULT_ACC=1`)

## Pull request expectations

- Every PR into `main` runs the full CI suite: `go vet`, `gofmt` check,
  `golangci-lint`, unit tests (race + coverage), acceptance tests, and
  cross-compile builds. **All checks must be green.**
- PRs require **one approving review from a code owner** before they can merge.
- Keep PRs focused and reasonably small; include tests for new behavior.
- Update documentation (`README.md`, `docs/`) when behavior changes.
- History is kept clean via **squash merge**, so a tidy PR title/description is
  appreciated.

### Sign-off (optional but appreciated)

You are encouraged to sign off your commits to certify the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "your message"
```

## Reporting bugs and requesting features

Use the issue templates under **New issue**. Provide reproduction steps,
expected vs. actual behavior, and the affected version where relevant.

Thank you for contributing!
