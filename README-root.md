# gcloud

A two-part authentication project. **v1** builds auth by hand to understand the
primitives. **v2** rebuilds the same concerns cloud-native on AWS.

> Building the fundamentals first means every managed service reached for
> afterwards is a deliberate choice, not a black box.

Design principle throughout: **every security layer maps to a specific, named
threat.** More layers is not more defence — it is more attack surface unless each
one earns its place.

**Mohammad Al Ahmad** — Cybersecurity student, APU Kuala Lumpur
Target role: Cloud Security Engineer

---

## Repository

```
gcloud/
├── v1-local/     Flask + PostgreSQL, built by hand      [COMPLETE]
└── v2-aws/       Terraform + Cognito + KMS + CloudTrail [IN PROGRESS]
```

---

## v1 — Local (complete)

Flask application with PostgreSQL in Docker. `/register`, `/login`, `/logout`,
and a protected `/welcome`, verified end to end.

**The ten decisions**

1. **Hashing, not encryption** — one-way versus reversible; encryption fails when
   the key leaks, and the key lives on the same server.
2. **Argon2id** — memory-hard, top of the OWASP ranking. bcrypt rejected: not
   memory-hard, truncates past 72 bytes.
3. **Benchmarked parameters** — `m=196608 (192 MiB), t=3, p=4` → ~201 ms/hash on
   an i5-8350U, 10× the OWASP floor. Measured, not copied. 256 MiB rejected on the
   memory calculation.
4. **Least exposure** — Postgres publishes no port; dev access bound to
   `127.0.0.1:5433`, never `0.0.0.0`.
5. **Username enumeration defence** — identical error for wrong password and
   unknown user; registration says "not available", not "taken".
6. **Validate before hashing** — bounds checks run before Argon2id, so a huge
   password cannot become a DoS amplifier.
7. **Soft delete** — `status='deleted'`, row retained for audit trail and
   referential integrity, and reversible.
8. **Account lockout** — 5 failures → 15 minutes, stored as an expiry timestamp so
   time releases it without a background job. Checked *before* password
   verification.
9. **IP trust boundary** — proxy headers honoured only when `TRUST_PROXY=1`.
   The header is not trusted; the deployment is.
10. **Secrets in `.env`** — `os.environ["X"]` so a missing value fails loudly.
    `SECRET_KEY` signs session cookies, preventing a forged `role: admin`.

Known gaps: no CSRF tokens, no local HTTPS (loopback only), weak development
database password.

Details: [`v1-local/`](v1-local)

---

## v2 — AWS (in progress)

Cognito for authentication; the project's effort moves to infrastructure
security — IAM, KMS, CloudTrail, all provisioned with Terraform and no console
clicking.

**Why managed auth:** companies do not hand-roll authentication, they secure
managed services. v1 already covers the application side, so "it becomes
infrastructure rather than application" is the point rather than a drawback.

Built so far:

| Component | Purpose |
|---|---|
| Cognito user pool | Password policy, TOTP MFA, enumeration defence |
| Cognito app client | SRP auth, no client secret, short token lifetimes |
| KMS customer-managed key | Explicit key policy as a second access boundary |
| CloudTrail | Multi-region audit logging, KMS-encrypted, validated |
| IAM role | Read-only trail access via temporary credentials |

Each control and the reasoning behind it: [`v2-aws/README.md`](v2-aws/README.md)
Decision log with rejected alternatives and operational mistakes:
[`v2-aws/NOTES.md`](v2-aws/NOTES.md)

---

## v1 → v2

| Concern | v1 (hand-built) | v2 (managed) |
|---|---|---|
| Password storage | Argon2id, benchmarked | Cognito-managed |
| Session | Signed Flask cookie | JWT, 60-minute access token |
| Brute force | Lockout table + timestamp | Cognito-managed |
| Enumeration | Identical error strings | `prevent_user_existence_errors` |
| Audit trail | Soft delete preserves rows | CloudTrail, account-wide |
| Secrets | `.env`, gitignored | KMS key policy, no secrets in code |
| Deployment | Docker Compose, local | Terraform, reproducible |

---

Nothing is claimed here that has not been built and tested.
