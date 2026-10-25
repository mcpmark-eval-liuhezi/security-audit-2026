# Security Audit 2026 — GitHub Account @HeziLiu

**Account:** HeziLiu (Hezi Liu) — https://github.com/HeziLiu
**Audit date:** 2026-10-25
**Purpose:** Annual lab security review. This document records the observed state of every repository owned by the account, exactly as each GitHub API check returned it, with no assumptions filled in.

---

## 1. Repository inventory

The account profile reports 4 public repositories and 0 public gists. A repository search including forks returned 4 repositories total (2 non-fork repositories plus 2 forks); no archived repositories and no private repositories owned by the account were found. The complete inventory:

| Repository | Type | Primary language | Default branch | Last pushed |
|---|---|---|---|---|
| [HeziLiu/Little-rookie](https://github.com/HeziLiu/Little-rookie) | Source repo ("Undergraduate coursework") | Java | `master` | 2019-06-02 |
| [HeziLiu/Big-Buzzard](https://github.com/HeziLiu/Big-Buzzard) | Source repo ("For future....") | None reported (repository is effectively empty apart from `.gitattributes` and an empty `Big-Buzzard` file) | `master` | 2018-05-17 |
| [HeziLiu/CodingInterviewChinese2](https://github.com/HeziLiu/CodingInterviewChinese2) | Fork ("《剑指Offer》第二版源代码") | C++ | `master` | 2019-03-12 |
| [HeziLiu/awesome-chatgpt-prompts-zh](https://github.com/HeziLiu/awesome-chatgpt-prompts-zh) | Fork ("ChatGPT 中文调教指南") | None reported (content repository: Markdown and JSON prompt collections) | `main` | 2023-04-14 |

## 2. Code scanning alerts

The code scanning alert check was run against each of the four repositories above. For **every** repository the check **could not be run**: the GitHub API returned

```
GET /repos/HeziLiu/{repo}/code-scanning/alerts -> 403 Resource not accessible by personal access token
```

| Repository | Result of code scanning alert check |
|---|---|
| HeziLiu/Little-rookie | Check could not be run — 403 "Resource not accessible by personal access token". No alert count or severity data was returned. |
| HeziLiu/Big-Buzzard | Check could not be run — 403 "Resource not accessible by personal access token". No alert count or severity data was returned. |
| HeziLiu/CodingInterviewChinese2 | Check could not be run — 403 "Resource not accessible by personal access token". No alert count or severity data was returned. |
| HeziLiu/awesome-chatgpt-prompts-zh | Check could not be run — 403 "Resource not accessible by personal access token". No alert count or severity data was returned. |

**Plainly stated:** zero alerts were *returned* for any repository, but that is because the endpoint is blocked for this token, not because the repositories were verified clean. The check needs to be re-run with a token carrying the `security_events` / code-scanning read scope before the audit can state a real alert count or severity breakdown.

## 3. Dependency advisories

**Dependency files in the audited repositories:**

- **HeziLiu/Little-rookie** — no dependency file. The repository root contains `.gitattributes`, an IntelliJ `.iml` module file and course directories; no `pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, `Gemfile`, `go.mod`, `Cargo.toml` or `composer.json` was found anywhere in the repository.
- **HeziLiu/Big-Buzzard** — no dependency file. The repository contains only `.gitattributes` and an empty `Big-Buzzard` file.
- **HeziLiu/CodingInterviewChinese2** — no dependency file. Fork of C++ sample code with no package manifest.
- **HeziLiu/awesome-chatgpt-prompts-zh** — no dependency file. Markdown/JSON content repository.

**Fallback applied:** since none of the repositories under the account declare dependencies, the audit fell back to the **pip** ecosystem as instructed, and queried GitHub's global security advisory database for high and critical reviewed advisories in that ecosystem.

**Advisories returned (pip ecosystem, high and critical):**

| Advisory ID | Severity | Affects | Summary |
|---|---|---|---|
| **GHSA-394h-qwmc-48pf** | high | `virtualenv` (PyPI) — xonsh activation literals | Caller-supplied prompt text can become executable syntax in the xonsh activation script when it is read with a legacy multibyte encoding (GBK/Big5) rather than UTF-8: the backslash escaping an embedded quote is consumed as a trail byte, the quote closes the Python string literal, and attacker-supplied statements run during activation. Requires attacker control of the prompt/destination value plus a user sourcing the generated script. CWE-94 (Code Injection). |
| **GHSA-5x8w-8jj5-q52h** | critical | `Pillow` (PyPI) — FlashPix (FPX) JPEG decoding | Heap buffer overflow (CWE-122 / CWE-787) in `FpxImagePlugin`'s JPEG-tile path: the output buffer is sized for the rawmode while libjpeg writes bytes-per-pixel taken from the attacker-controlled SOF marker, producing a heap out-of-bounds write with attacker-controlled length and content that is weaponizable to arbitrary code execution on a single `Image.open()`. Reachable with no user interaction by any service that thumbnails untrusted uploads, since FPX files are detected by OLE2 content magic rather than extension (requires the optional `olefile` dependency). |

Advisory links: [GHSA-394h-qwmc-48pf](https://github.com/advisories/GHSA-394h-qwmc-48pf) · [GHSA-5x8w-8jj5-q52h](https://github.com/advisories/GHSA-5x8w-8jj5-q52h)

**Caveat for the reviewer:** these advisories are ecosystem-wide results from the fallback query. None of the audited repositories pins `virtualenv` or `Pillow` (or any other package), so there is no direct exposure through the repositories themselves; the findings document the ecosystems checked rather than confirmed vulnerabilities in audited code.

## 4. Discussions

The discussions check was run against each of the four repositories. **No repository has any discussions** — every repository returned an empty discussion list (`totalCount: 0`), and all four repositories also report `has_discussions: false` (the Discussions feature is not enabled on any of them).

| Repository | Discussions |
|---|---|
| HeziLiu/Little-rookie | None — 0 discussions, feature disabled |
| HeziLiu/Big-Buzzard | None — 0 discussions, feature disabled |
| HeziLiu/CodingInterviewChinese2 | None — 0 discussions, feature disabled |
| HeziLiu/awesome-chatgpt-prompts-zh | None — 0 discussions, feature disabled |

There are consequently no discussion threads to summarize and no last commenters to report.

---

## Summary and follow-ups

1. **Repo inventory:** 4 repositories (2 source, 2 forks), primary languages Java and C++ where reported.
2. **Code scanning:** check blocked by token scope on all 4 repositories — re-run with a code-scanning-capable token to get real counts.
3. **Dependencies:** no dependency manifests anywhere in the account; pip fallback query returned GHSA-394h-qwmc-48pf (high, `virtualenv`) and GHSA-5x8w-8jj5-q52h (critical, `Pillow`).
4. **Discussions:** none in any repository.

Tracking issue with sub-issues: Security audit tracker (#8).
