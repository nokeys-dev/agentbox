# External security review plan

Companion to `docs/security-review-scope.md` (what is reviewed) and `SECURITY.md` (how
findings are reported). This is the plan for getting an independent, publishable review done.

## What we are buying

A source-assisted penetration test of the broker stack against the attacker models in the scope
document: a hostile agent in the workspace holding the client token; another host on the broker
network; malicious repository, issue, and pull request content; a compromised reviewer browser;
a compromised CI or release pipeline. Two to three engineer-weeks. Not a SOC 2 audit, which
certifies process rather than product and comes when procurement asks.

## Firms and funding

Commercial, source-assisted, publish reports: Trail of Bits, NCC Group, Cure53, Doyensec,
Include Security, X41 D-Sec, Radically Open Security, 7ASecurity. Ask three for a fixed-price
quote against the scope document; expect roughly 25,000 to 60,000 dollars from the boutiques.
The contract must allow publication of the final report after remediation.

Funded for open source: the Open Source Technology Improvement Fund (OSTIF) and the OpenSSF
Alpha-Omega program fund audits and choose the firm. Apply as soon as the license is in place;
lead time is months, so run this in parallel with commercial quotes.

Free but not publishable: a design partner's internal red team on the pilot deployment.

## Before the engagement

1. License file in the repository (the funded programs require it).
2. Freeze a release tag; put its commit hash at the top of the scope document.
3. Give the testers a one-command deployment (`npm run bootstrap`, the Compose files, and the
   enterprise overlay with a test identity provider) and a hosted instance they can attack
   without us in the loop.
4. Hand over `THREAT_MODEL.md`, `npm run demo`, `npm --prefix enterprise run demo:identity`, and
   `npm run test:fleet` so they spend hours, not days, learning the system.
5. Confirm the scope covers fleet mode, the issuer, KMS signing, gateway and proxy attribution,
   the entitlement sources, and strict assertion parsing.
6. State non-goals: no denial of service against upstream providers, no attacks on the identity
   provider or KMS themselves, no social engineering.

## During

One engineer on call on a shared channel. Findings triaged within a day; anything that breaks a
threat-model claim is fixed on a branch immediately so it can be re-tested inside the engagement.

## After

- Fix every high and critical finding, then have the firm re-test and mark them fixed in the
  report. Unfixed findings in a public report cost more than no report.
- Publish the report at nokeys.dev next to the threat model and link it from `SECURITY.md`.
- Update `THREAT_MODEL.md` for anything the review changed about the stated limits.
- Reference the report on the deck's security slide and in design-partner outreach.

## Timeline

Quotes and OSTIF application now; engagement booked for after the license and the first design
partner, so the reviewed code is the code they run. Six to ten weeks from the decision.
