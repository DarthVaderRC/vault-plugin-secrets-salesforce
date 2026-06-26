# Analysis: Salesforce limits that could affect the OAuth token-management secrets engine

This document assesses whether Salesforce platform limits could **hinder or block** building
`vault-plugin-secrets-salesforce` (JWT Bearer + Client Credentials flows, cache/lease model).

It revises an earlier draft. Each claim is graded **Accurate / Partially accurate /
Inaccurate**, with the corrected fact and a confidence level. Facts marked **[confirmed]**
were verified against Salesforce's official *API Request Limits and Allocations* doc
(`developer.salesforce.com`, API v262). Facts marked **[expert / unverified this session]**
reflect well-established Salesforce behavior but were **not** re-confirmed against primary
docs here and should be validated before we rely on them.

> **Bottom line up front:** None of these limits *block* development. They are
> configuration and design constraints. The caching/leasing architecture in
> `SPECIFICATION.md` is the correct mitigation and is, if anything, *more* important than
> the original draft argued: but for partly different reasons than it stated.

---

## Verdict summary

| # | Claim in original draft | Verdict | Corrected fact |
|---|---|---|---|
| 1 | 3,600 logins/hour/user; exceeding locks the integration user | **Partially accurate / overstated** | Real throttling exists, but the specific "3,600/hour" number and "locks the user" are **not** in official OAuth docs. It conflates legacy SOAP `login()` behavior with OAuth token minting. |
| 2 | Max 5 active access tokens per Connected App per user; 6th invalidates the 1st | **Partially accurate / needs verification** | Salesforce **does** cap OAuth tokens per user/app and evicts the oldest, but the exact number is configurable/edition-dependent and the cap historically concerns the **refresh-token/approval** relationship: JWT Bearer & Client Credentials issue access tokens **without** a refresh token, so this behaves differently. |
| 3 | Token-minting requests count against the org's 24-hour API allocation | **Inaccurate (premise)** | **[confirmed]** The 24-hour allocation counts REST/SOAP/Bulk/Connect **data** API calls. OAuth **authentication** calls are not in that list and do not consume the allocation. |
| 4 | Token endpoint returns 429 + `Retry-After` when throttled; back off | **Reasonable / good practice** | Salesforce can throttle and return errors; defensive backoff is correct. Exact 429/`Retry-After` semantics on the token endpoint were not confirmed this session. |

---

## 1. "Hourly login rate limit": Partially accurate / overstated

**Original claim:** 3,600 logins/hour/user (1/sec); exceeding triggers *Login Rate Exceeded*
and locks the integration user.

**Assessment:**
- Salesforce **does** apply rate limiting at the authentication layer and **does** have a
  *"login rate exceeded"* style throttle **[expert / unverified this session]**.
- However, the precise **"3,600 per hour"** figure and the claim that it **locks** the user
  are **not** found in Salesforce's official OAuth/limits documentation. The number is
  widely repeated community lore and is most associated with the **legacy SOAP `login()`
  call**, not the OAuth `grant_type=jwt-bearer` / `client_credentials` token endpoint.
- What *is* officially documented and adjacent **[confirmed]**: **Concurrent API request
  limits**: requests lasting **≥ 20 seconds**: **25** concurrent for Production/Sandbox,
  **5** for Developer/Trial orgs; exceeding returns `REQUEST_LIMIT_EXCEEDED`. Token minting
  is sub-second, so this concurrent limit is essentially irrelevant to the engine.

**Why the engine is fine:** Caching means Salesforce sees one token mint per role per
`token_ttl` window (minutes/hours), not per caller request. Even a fleet of microservices
produces a trickle of auth events. The mitigation logic holds; the specific number does not.

**Action for the spec:** Do not cite "3,600/hour" as fact. Keep per-role mint throttling +
mutex (already designed) as defense-in-depth.

## 2. "5-token concurrent cap per Connected App": Partially accurate / needs verification

**Original claim:** A user may hold at most 5 active access tokens for one Connected App; a
6th silently revokes the 1st, causing 401s for the older token's holder.

**Assessment:**
- Salesforce **does** impose a per-user/per-connected-app cap on outstanding OAuth tokens
  and **evicts the oldest** when exceeded: the *behavior* the draft describes is real
  **[expert / unverified this session]**.
- But the exact number (**5**) is **not confirmed** here, is **edition/configuration
  dependent**, and the classic "oldest token revoked" cap historically governs the
  **refresh-token / user-approval** relationship. **JWT Bearer and Client Credentials issue
  access tokens with NO refresh token and (for Client Credentials) no per-user approval**,
  so the eviction dynamics differ from the interactive/refresh-token case.

**Why this still matters for the engine (and supports caching):** Regardless of the exact
number, an engine that mints a **fresh** token on **every** read (the rejected "Option 2")
would rapidly churn tokens for a single run-as identity and could trip whatever cap exists,
invalidating tokens already handed to callers → intermittent 401s. The **caching model
avoids this entirely** by holding one token per role and re-minting only near expiry. This
is a strong, independent reason to keep caching: arguably the strongest in this document.

**Action for the spec:** Treat "minting churns/evicts tokens" as a real risk and keep the
single-cached-token-per-role design. **Verify the exact cap** against the current
*Connected Apps / OAuth* docs and your org's session settings before launch. Add a config
note that aggressive `rotate`/no-cache usage can self-inflict 401s.

**Measured (real-org E2E, 2026-06-24, Developer Edition):** Minting **8 tokens in a row**
for the same user/app/scope via JWT Bearer (and separately Client Credentials) returned the
**identical access token every time**: Salesforce **reuses the existing valid session token**
rather than issuing new ones, and all 8 remained valid. **Conclusion:** under this engine's
normal usage pattern (one run-as identity per role), you do **not** accumulate tokens toward
any per-user/per-app cap, because repeated grants are de-duplicated **server-side**. The cap
only becomes reachable if tokens are forced to be distinct (e.g. explicit `/revoke` between
mints, or differing scopes). This **reinforces** the "no blocker" verdict and means even the
caching layer's worst case (a brief thundering-herd of concurrent cold-cache reads) is largely
absorbed by Salesforce's own token reuse: though the in-engine cache + a future mint mutex
(Stage 2 / T11) remain the right design to avoid redundant auth round-trips.

## 3. "Token minting counts against the 24-hour API allocation": Inaccurate premise

**Original claim:** Token-minting requests count against tenant API allocations / trigger
429s; caching saves your daily API budget.

**Assessment [confirmed]:** Per *API Request Limits and Allocations*:
- The 24-hour allocation counts **data** APIs: *"Lightning Platform REST API, … SOAP API,
  Bulk API, Bulk API 2.0, and most Connect REST APIs."*
- OAuth **authentication / token** calls are **not** in that list. Authentication is not a
  consuming API call, so **minting tokens does not draw down the daily API allocation.**
- Allocation sizing (for context): Developer Edition = **15,000**/24h; Enterprise/Unlimited
  = **100,000 + (licenses × per-license calls) + add-ons**.

**Net:** The premise ("minting eats your API budget") is wrong. Caching is still worthwhile
(fewer auth round-trips, lower latency, fewer chances to hit auth-layer throttling), but
**not** because it preserves the 24-hour data-API allocation. Fix this framing in the doc.

## 4. "429 / Retry-After handling": Reasonable, good practice

Salesforce can throttle and return error responses under load; implementing exponential
backoff and honoring `Retry-After` if present is sound defensive engineering. Exact
`429`/`Retry-After` semantics on `/services/oauth2/token` were not confirmed this session:
treat backoff as best-effort resilience, not a documented contract.

---

## Other Salesforce constraints that genuinely affect the engine

These are **real, high-impact** design/setup constraints (mostly **[expert]** knowledge;
flagged where confirmed). None are blockers, but the engine and its runbook must handle them.

1. **Access tokens have no `expires_in` in the response.** Salesforce token responses
   generally omit `expires_in`; token lifetime is governed by the **Connected App session
   policy** and the **org session-timeout** settings. → The engine **cannot** read expiry
   from the response and must treat TTL as a **configured role parameter** (`token_ttl`).
   *This is already correctly designed in `SPECIFICATION.md` §2.5/§7.* Optionally use the
   **introspection endpoint** to get an authoritative `exp`.

2. **JWT Bearer requires the run-as user to be pre-authorized for the Connected App.**
   Either "Admin approved users are pre-authorized" + assignment via Permission Set/Profile,
   or a prior user approval. Otherwise the token call fails with
   `invalid_grant: user hasn't approved this consumer`. → A **setup prerequisite**, surfaced
   in the deployment runbook, not a runtime blocker.

3. **Client Credentials flow prerequisites.** Requires **My Domain**, the flow explicitly
   enabled on the (External Client / Connected) App, and a **run-as user assigned**. Missing
   any of these → `invalid_client` / flow-not-enabled errors.

4. **My Domain & endpoint host.** Salesforce is steering orgs to
   `https://<MyDomain>.my.salesforce.com` OAuth endpoints and deprecating reliance on bare
   `login.salesforce.com` for some scenarios. → `config.login_url` must support My Domain
   (already in the spec). Use `test.salesforce.com`/My Domain for sandboxes.

5. **Login IP ranges / IP relaxation.** If the Connected App enforces IP restrictions, token
   requests from Vault's egress IP can be rejected. → Operators must allowlist Vault's egress
   or relax IP enforcement on the app.

6. **JWT assertion clock-skew window.** Salesforce rejects assertions whose `exp` is too far
   in the future (treat ~3 min as safe, ≤5 min max) and is sensitive to host clock drift. →
   Keep `jwt_expiry ≤ 5m` (already in spec) and ensure the Vault host clock is accurate.

7. **Sharing one access token across many callers is safe.** Salesforce OAuth access tokens
   are stateless bearer tokens; multiplexing one cached token to many consumers does not
   violate concurrent-session limits the way interactive UI sessions can. This validates the
   cache-and-share design. (Confirm no org-specific "session-based" token policy forces
   per-session binding.)

---

## Blocker assessment

| Concern | Blocks development? | Notes |
|---|---|---|
| Concurrent API limit (25 / ≥20s) **[confirmed]** | No | Token mints are sub-second. |
| 24-hour API allocation **[confirmed]** | No | Auth calls don't consume it. |
| Token-per-app eviction cap | No | Caching avoids churn; verify exact number. |
| Auth-layer rate limiting | No | Caching + backoff. |
| No `expires_in` on token | No | Designed for: configured `token_ttl` (+ optional introspection). |
| JWT pre-authorization / CC run-as / My Domain / IP | No | Setup prerequisites in the runbook. |

**Conclusion:** **No blockers.** Salesforce has no published limit that prevents a Vault
secrets engine from brokering OAuth tokens. The cache/lease design is correct and is the
primary mitigation for the limits that do exist. Before launch, **verify Claim 2's exact
token cap** and the auth-layer rate-limit specifics against current primary docs and the
target org's session settings.

---

## Sources

- **API Request Limits and Allocations**: *Salesforce App Limits Cheat Sheet*,
  `developer.salesforce.com` (verified this session; basis for all **[confirmed]** facts:
  concurrent limits 25/5 for ≥20s requests, `REQUEST_LIMIT_EXCEEDED`, 24-hour allocations,
  and the list of APIs that count toward the allocation).
- OAuth flow specifics (JWT Bearer pre-authorization, Client Credentials run-as/My Domain,
  token TTL governed by session policy, token-per-app eviction): **Salesforce Help / OAuth
  and Connected Apps** documentation: **to be re-verified against primary docs** before we
  depend on the exact numbers (the help.salesforce.com OAuth articles did not render cleanly
  for capture in this session).
