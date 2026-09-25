# v2 (AWS) — Decisions Log

Written while building. Each entry records what was chosen, why, what was
rejected, and what would change the decision.

Region: `ap-southeast-1` · Provider: `hashicorp/aws ~> 5.0` (locked at 5.100.0)

---

## Cognito — User Pool

**Password policy: 16 chars, all four composition classes required.**
v1 enforced 10 with a manual bounds check. v2 raises it. Rejected 8 (Cognito's
default) — taking an unexamined default contradicts the project's rule that
every layer is a deliberate choice.

Tradeoff acknowledged: NIST SP 800-63B dropped mandatory composition rules,
because forcing symbol/number classes pushes users toward predictable patterns
(`Passw0rd!`). Length does more work than class count. 16 + all four classes is
stricter than necessary and mildly hostile to users. Kept because this is a
demonstration project with no real user base; a production pool would drop
composition and keep the length.

Cognito's base tier has no breached-password checking. That is a real capability
loss versus hand-rolled auth — the managed service's defaults are sane but
cannot be tuned past what AWS exposes.

**MFA: `OPTIONAL` with software token (TOTP) only.**
`ON` forces every user through MFA enrolment and requires a second factor method
configured before the pool will create. `OPTIONAL` without any method enabled is
rejected by Cognito outright — the API returns
`InvalidParameterException: SMS MFA, Email MFA, or Software Token MFA must be
enabled`. The mode and the method are one decision, not two.

TOTP over SMS: SMS is vulnerable to SIM-swap, costs money per message, and needs
an SNS configuration. NIST downgraded SMS as an authenticator for the same
reason.

**Account recovery: `verified_email`, priority 1.**
Recovery is the most common account-takeover path — it is an alternate way in,
not a side feature. Email only; no phone fallback.

**`deletion_protection = "ACTIVE"`.**
Default is `INACTIVE`, meaning a `terraform destroy` or an accidental
destroy-and-recreate silently wipes the pool and every user in it. No export,
no undo. See *Operational lessons* — this was enabled too early and caused a
deadlock.

---

## Cognito — App Client

**`generate_secret = false`.**
Browser code is fully visible to the user. A secret shipped to a public client
is not a secret. Client secrets are for confidential clients (server-side) only.

**Auth flows: `ALLOW_USER_SRP_AUTH` + `ALLOW_REFRESH_TOKEN_AUTH`.**
Rejected `ALLOW_USER_PASSWORD_AUTH`, which sends the plaintext password to
Cognito over TLS. SRP proves knowledge of the password without the password ever
leaving the device — so a compromised TLS terminator or a logging misconfig
never sees it. `ALLOW_REFRESH_TOKEN_AUTH` is required or sessions cannot be
renewed and users are ejected when the access token expires.

**Token lifetimes: refresh 7 days, access 60 min, id 60 min.**
Default refresh validity is 30 days — a stolen refresh token is valid for a
month. 7 days trades user convenience for a shorter exploitation window. 60
minutes on access/id bounds the damage of a leaked bearer token.

**`prevent_user_existence_errors = "ENABLED"`.**
This is the managed equivalent of v1's username-enumeration defence — the
identical `"Incorrect username or password"` for both a wrong password and a
non-existent user, hand-written in `app.py`. Cognito reduces it to one field.
That contrast is the whole v1→v2 argument: knowing what the flag does is the
reason it was switched on deliberately rather than left at `LEGACY`.

---

## KMS

**Customer-managed key over the S3 `AES256` default.**
The v1 test bucket showed `sse_algorithm = "AES256"` — AWS-managed encryption,
enabled without being asked for. It works, but the key is invisible: its use
cannot be restricted and cannot be audited. A CMK makes the **key policy a second
access boundary, independent of IAM** — an identity with IAM permission on the
data still cannot decrypt it without permission on the key.

**`deletion_window_in_days = 14`.**
Deleting a KMS key destroys every ciphertext under it, permanently. AWS enforces
a 7–30 day waiting period during which deletion can be cancelled. 14 gives two
weeks to notice a mistake without leaving the key in limbo for a month.

**`enable_key_rotation = true`.**
AWS generates new key material annually and retains old material for decrypting
existing data. Limits the volume of ciphertext produced under any single piece of
key material.

**Explicit key policy — three statements.**

1. `EnableIAMUserPermissions` — account root, `kms:*`. **Mandatory.** A key policy
   replaces the default entirely rather than merging with it; the apply diff
   showed AWS's `Id = "key-default-1"` being removed. Omitting this statement
   makes the key permanently unmanageable, with no recovery path. This is what
   Terraform's `bypass_policy_lockout_safety_check` guards against.
2. `AllowCloudTrailEncrypt` — `kms:GenerateDataKey*` for
   `cloudtrail.amazonaws.com`. Not `kms:Encrypt`: KMS uses envelope encryption,
   generating a per-object data key rather than encrypting objects directly.
   Constrained by `kms:EncryptionContext:aws:cloudtrail:arn` matching a trail in
   **this account only** — without that condition, any AWS account that learns the
   key ARN could have CloudTrail use it (confused-deputy).
3. `AllowCloudTrailDescribe` — `kms:DescribeKey`, required for CloudTrail to
   validate the key before enabling the trail.

**Evidence the boundary is real:** `CreateTrail` failed with
`InsufficientEncryptionPolicyException` while `terraform-admin` held
`AdministratorAccess`. IAM permission was not sufficient — only adding statements
to the key policy made it work.

**Alias `alias/gcloud-v2`** — key IDs are UUIDs. An alias is a readable handle
that can be repointed at a different key without editing every consumer.

**Cost:** $1/month per key. First component in the project that is not free tier.

---

## CloudTrail

Account-wide API audit logging. Conceptually the audit trail that v1's soft
delete preserved, at account scope: who called what, when, from which IP, and
whether it succeeded.

**Log bucket hardening.**
- All four `public_access_block` flags `true`. Trail logs are a complete map of
  the account's infrastructure and activity; any public exposure is a
  reconnaissance gift.
- Versioning `Enabled`. Overwriting an object no longer erases the previous
  version. The first thing an intruder does after acting is delete the evidence.

**Bucket policy — service principal, narrow resource.**
`Principal = { Service = "cloudtrail.amazonaws.com" }` grants to the AWS service,
not to a user. `s3:PutObject` is scoped to
`<bucket-arn>/AWSLogs/<account-id>/*`, not the whole bucket — least privilege
applied at the resource, not just the identity. The
`s3:x-amz-acl = bucket-owner-full-control` condition ensures written objects stay
owned by this account.

The account ID comes from `data "aws_caller_identity" "current"` rather than being
hardcoded, so the config is not bound to one account.

**Trail settings.**
- `is_multi_region_trail = true` — a single-region trail is blind to anything done
  in another region. Creating resources in an unmonitored region is a standard
  evasion.
- `enable_log_file_validation = true` — CloudTrail hashes and signs delivered
  logs. This does not *prevent* tampering; it makes tampering *detectable*.
  Detection, not prevention.
- `kms_key_id` → the CMK above. Read access to the bucket alone is insufficient;
  decryption requires permission on the key as well.
- `depends_on = [aws_s3_bucket_policy.trail]` — CloudTrail test-writes to the
  bucket during creation. Terraform infers ordering from references, but nothing
  in the trail block references the policy, so the dependency is declared
  explicitly.

---

## IAM

**Role `gcloud-v2-cloudtrail-reader`.**
A role, not a user: no long-lived access key, credentials are issued by STS and
expire (`max_session_duration = 3600`). `assume_role_policy` answers *who may
become this role* — a separate question from *what may it do*. That separation is
the point of roles.

**Attached policy — read-only investigation access.**
- `s3:GetObject` / `s3:ListBucket` on the trail bucket only. No `PutObject`, no
  `DeleteObject` — an investigator reads logs and cannot alter them.
- `kms:Decrypt` on this key ARN only. Cannot encrypt, cannot schedule deletion,
  cannot touch other keys.
- `cloudtrail:DescribeTrails` / `GetTrailStatus` / `LookupEvents` for metadata.

Both layers still apply: even with `kms:Decrypt` in the role policy, the key
policy must independently permit the principal.

> **Status: written and planned; confirm applied before relying on this section.**

---

## Operational lessons

**Deletion protection belongs on a settled config, not a work-in-progress.**
`mfa_configuration` changes can force resource replacement. Replacement means
destroy-then-create. Deletion protection blocks the destroy. Result: a deadlock
where the config cannot move forward or back, resolved only by a sequence of
single-variable applies — protection off, then the MFA change, then protection
back on. Enable the guardrail last.

**A failed apply can leave a resource tainted.**
The first apply created the pool, then failed on the MFA step. Terraform marked
the resource tainted — *exists, but may be in an invalid state* — and a tainted
resource is replaced on every subsequent plan regardless of configuration.
Editing the config had no effect because the config was not the cause.
`terraform untaint <address>` clears it.

**Change one variable per apply.** Two simultaneous changes made it impossible to
tell which one the error belonged to, and cost several wasted cycles.

**`.gitignore` before the first `.tf` file.**
`terraform.tfstate` records everything Terraform built, including secret values,
in plaintext — and it is generated automatically rather than written by hand, so
it is easy not to notice. Same lesson as `.env` in v1, higher stakes.

**`.terraform.lock.hcl` is committed, `terraform.tfstate` is not.**
Opposite rules for two similar-looking files. The lock file holds provider
versions and checksums — no secrets — and pins the exact provider across
machines, with the hash preventing a substituted provider. State holds the
secrets.

---

## Known gaps

- **`terraform-admin` still holds `AdministratorAccess`.** Accepted as a starting
  point because it is revocable and auditable, unlike root. The plan is to read
  CloudTrail for the API calls Terraform actually makes and write a scoped policy
  from that evidence — measure, don't copy, the same method used for the Argon2id
  parameters in v1. Now unblocked, since CloudTrail is live.
- **Long-lived access key on the laptop.** The IAM console warns against this:
  *avoid long-term credentials; use short-term credentials instead.* An access key
  never expires. The correct answer is IAM Identity Center or `sts:AssumeRole`.
  Accepted for a solo project on a 183-day credit window; recorded as a known
  compromise, not an oversight.
- **State is local and unencrypted.** Production practice is an encrypted S3
  backend with DynamoDB state locking. Next infrastructure task.
- **The KMS key policy still grants the account root `kms:*`,** from which IAM
  permissions derive. The key is therefore not yet a fully independent boundary
  for administrators — only for service principals and scoped roles.
- **MFA on `terraform-admin` gates console sign-in only.** It does not apply to
  access keys; API calls carry no second factor. Enforcing that requires an
  `aws:MultiFactorAuthPresent` policy condition and MFA-backed session tokens,
  which breaks plain `aws configure`.
