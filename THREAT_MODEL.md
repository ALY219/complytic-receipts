# Threat Model

## What this proves

- A statement was submitted to the database driver, with these parameters, at this time,
  by this principal.
- A signature exists over that record from a key identified by `key_id`.
- The record has not changed since it was sealed.
- Alteration, deletion, reordering, and forged outcomes are detected by the verifier.

## What this does NOT prove

### 1. Bypass is not prevented
If the agent runs in the same process and holds database credentials, it can open its
own connection and write without producing a receipt. Driver-level wrapping proves what
passed through the wrapper, not that everything went through it.

Closing this requires the agent to hold no database credentials and reach data only
through a gateway it does not control. **Not built.**

### 2. Payload provenance is partial
The receipt is built from the SQL and parameters handed to the driver, not from agent
self-report. It does not prove the agent's reasoning was honest. It does not prove the
database reported truthfully. It does not prove the business intent was legitimate.

### 3. Tamper-evident is not immutable
A hash chain makes alteration detectable. It does not make alteration impossible.
We do not claim immutability.

### 4. No legal or evidentiary status is claimed
Whether a record is admissible is a determination for a court, not a vendor. This
project does not claim FRE 902 compliance or any equivalent.

### 5. Timestamps are signer-local
`ts` is the signer's clock. No trusted timestamping authority is used. Clock
manipulation by the host is in scope for an attacker with host control.

### 6. Key isolation depends on deployment mode
| Mode | Key location | Isolation |
|---|---|---|
| `local-dev-in-process` | agent process memory | **none** |
| `remote-isolated-process` | separate process | process boundary only |
| `aws-kms-non-exportable` | AWS KMS | non-exportable key, IAM-scoped |

Only the third mode provides a meaningful answer to "the agent could forge receipts."

## Known limitations
- `executemany`, stored procedures, and ORM bulk paths are not wrapped.
- Sealing before execute adds one signing round trip per statement.
- No log truncation protection beyond `seq` continuity within a single chain file.
- No multi-writer chain merging.

## Reporting
If you find a way to alter a record without detection, open an issue. That is the
point of publishing this.