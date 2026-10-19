# Security footprint audit — 2026

Owner: @HeziLiu · Snapshot of the live account state at audit time. No assumptions — this is what the account actually looks like.

## Gist inventory

- **Gists on the account: none (0).**
- The authenticated-user gist listing returned an empty result, and the account profile reports 0 public gists.
- Nothing to inventory — no public gists, no secret gists visible to the account.
- This is an empty inventory by inspection, not a lookup failure.

## Organization advisories

- **Organizations you belong to: 1** — `mcpmark-eval-liuhezi` (membership confirmed; no teams within the org).
- **Org-wide repository security advisories:** the organization security-advisories endpoint is not accessible to the token in use (`403 Resource not accessible by personal access token`), so an org-wide listing could not be produced.
- **Per-repository advisory checks** were run against every org repository reachable with this token. **No repository security advisories on record in any checked repository:**

| Repository | Advisories on record |
| --- | --- |
| `mcpmark-eval-liuhezi/shanghai-trip-plan` | none |
| `mcpmark-eval-liuhezi/pub-quiz-internet-culture` | none |
| `mcpmark-eval-liuhezi/throwback-friday` | none |
| `mcpmark-eval-liuhezi/mcp-study-resources` | none |
| `mcpmark-eval-liuhezi/aapl-options-onboarding` | none |
| `mcpmark-eval-liuhezi/deploy-runbook` | none |
| `mcpmark-eval-liuhezi/cbdc-reading-list` | none |
| `mcpmark-eval-liuhezi/onboarding-runbook-demo` | none |
| `mcpmark-eval-liuhezi/release-drill-lab` | none |
| `mcpmark-eval-liuhezi/security-audit-2026` | none |

- **Not verifiable with this token:** the org's private repositories (e.g. `paper-reading-series`, `copilot-review-trial`) return 404 from the advisory endpoint — the token cannot see them — so their advisory status is unknown, not "clear".

## Bottom line

- Gist footprint: empty — no exposure via gists.
- Organization advisory exposure: no advisories found on record in any org repository verifiable with the current token; the org-wide advisory view and private repositories are blocked by token permissions and would need a re-check with an org-admin-scoped token to fully close out.

_Audit record: see issue #6 in this repository for the same findings._
