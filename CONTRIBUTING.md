# Contributing

Thank you for working on AgentBox. A few rules keep the security story intact.

- **Sign off every commit** (`git commit -s`). This applies the Developer Certificate of Origin
  (https://developercertificate.org): you certify that you wrote the change or have the right to
  submit it under the project's license.
- **No new npm dependencies** in `src/`. The broker ships with zero runtime dependencies on
  purpose; a dependency is a supply-chain surface the buyer has to trust.
- **Tests first.** Every behaviour change comes with a test under `test/`. `npm run check` and
  `npm test` must pass, and image or Compose changes must pass `npm run test:docker` and
  `npm run test:fleet`.
- **Keep the documents honest.** A change that alters what the system protects against updates
  `THREAT_MODEL.md`; a new capability updates `ROADMAP.md` and the relevant `docs/` page in the
  same pull request.
- **Never log a secret.** Tokens, assertions, provider keys, and request bodies do not appear in
  logs, audit records, error messages, or test output.
- **Security bugs go to SECURITY.md**, not to a pull request.
