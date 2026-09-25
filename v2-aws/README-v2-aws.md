# gcloud v2 — Cloud-Native Auth on AWS

Terraform-provisioned authentication and audit infrastructure on AWS. This is the
second half of a two-part project: [v1](../v1-local) built authentication by hand
to understand the primitives; v2 rebuilds the same concerns on managed services
and spends the saved effort on infrastructure security instead.

**Every security control here maps to a specific, named threat.** More layers is
not more defence — each one has to earn its place.

> Full decision log, including rejected alternatives and operational mistakes:
> **[NOTES.md](NOTES.md)**

---

## Architecture

```
                    ┌─────────────────────┐
   sign-in  ───────▶│  Cognito User Pool  │  password policy, TOTP MFA,
                    │  gcloud-user-pool   │  enumeration defence
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  App Client (web)   │  SRP auth, no client secret,
                    │                     │  short token lifetimes
                    └─────────────────────┘

   every API call in the account
              │
   ┌──────────▼──────────┐      ┌────────────────────┐
   │     CloudTrail      │─────▶│   S3 log bucket    │  versioned, fully
   │  multi-region       │      │                    │  private
   │  log validation     │      └─────────┬──────────┘
   └─────────────────────┘                │ encrypted with
                                ┌─────────▼──────────┐
                                │   KMS CMK          │  key policy = second
                                │   alias/gcloud-v2  │  access boundary
                                └─────────┬──────────┘
                                          │ decrypt permitted to
                                ┌─────────▼──────────┐
                                │  IAM role          │  read-only, temporary
                                │  cloudtrail-reader │  credentials
                                └────────────────────┘
```

## Resources

| File | Provisions |
|---|---|
| `main.tf` | Provider, region, credentials profile |
| `cognito.tf` | User pool + web app client |
| `kms.tf` | Customer-managed key, explicit key policy, alias |
| `cloudtrail.tf` | Log bucket, bucket hardening, bucket policy, trail |
| `iam.tf` | `cloudtrail-reader` role, scoped read-only policy, attachment |

## Security controls

**Cognito user pool** — 16-character minimum password; TOTP MFA (optional, SMS
rejected for SIM-swap exposure); email-only account recovery; deletion protection
active.

**App client** — no client secret (browser code hides nothing); SRP auth so the
password never leaves the device; refresh tokens 7 days instead of the 30-day
default; `prevent_user_existence_errors` enabled — the managed equivalent of v1's
hand-written username-enumeration defence.

**KMS** — customer-managed key rather than the S3 `AES256` default, so key usage
can be restricted and audited. Explicit key policy scopes CloudTrail to
`GenerateDataKey*` only, conditioned on an encryption context matching a trail in
this account — without that condition, any account that learns the key ARN could
use it. Annual rotation; 14-day deletion window.

**CloudTrail** — multi-region (a single-region trail is blind to activity
elsewhere); log file validation for tamper *detection*; logs encrypted with the
CMK, so bucket access alone does not grant readability. Bucket blocks all public
access and has versioning enabled, because deleting evidence is the first
post-compromise move.

**IAM** — `cloudtrail-reader` is a role, not a user: no long-lived key,
credentials expire in an hour. Read-only on the trail bucket, `kms:Decrypt` on one
key ARN, CloudTrail metadata reads. No write or delete anywhere.

## Verified

Each control was exercised, not just applied:

| Check | Result |
|---|---|
| CloudTrail delivering | Log objects present under `AWSLogs/.../ap-southeast-1/` |
| Multi-region | Digest files across **16 region prefixes** |
| Log file validation | Digest files exist — CloudTrail produces them only when enabled |
| KMS in the encryption path | `ServerSideEncryption: aws:kms`, `SSEKMSKeyId` = the `alias/gcloud-v2` key |
| Least privilege | `PutObject` → `AccessDenied` under the reader role; `ListBucket` succeeds |

The denial names its own mechanism — *"no identity-based policy allows the
s3:PutObject action"*. There is no explicit `Deny` in the policy; the write fails
because the permission was never granted.

## Usage

```bash
terraform init
terraform plan
terraform apply
```

Requires an AWS CLI profile named `terraform-admin` (see `main.tf`) and
`ap-southeast-1` as the region.

## Files never committed

```
*.tfstate            # records everything built, secrets in plaintext
*.tfstate.*
.terraform/          # provider binaries
*.tfvars             # real variable values
```

`.terraform.lock.hcl` **is** committed — provider versions and checksums, no
secrets, and it pins the exact provider across machines.

## Known gaps

- `terraform-admin` still holds `AdministratorAccess`; the plan is to derive a
  scoped policy from CloudTrail's record of the calls Terraform actually makes.
- State is local and unencrypted. Production practice is an encrypted S3 backend
  with DynamoDB locking.
- Long-lived access key on a laptop. IAM Identity Center or `sts:AssumeRole`
  would issue expiring credentials instead.

Recorded as compromises, not oversights — reasoning in
[NOTES.md](NOTES.md#known-gaps).
