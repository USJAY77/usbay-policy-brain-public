# Deployment Certificate Chain

Planning status: architecture draft only. No runtime enforcement, production code, CI, or signing behavior is changed by this document.

## Scope

The Deployment Certificate Chain is a proposed proof chain that binds a customer deployment to signed release provenance, policy bundle identity, tenant scope, and runtime authority lineage.

```
Release Manifest
      |
      v
Deployment Certificate
      |
      v
Customer Deployment Certificate Chain
      |
      v
Customer Evidence Layer
```

## Trust Boundaries

- Release boundary: signed governance release metadata.
- Deployment boundary: customer deployment certificate generated from release and tenant metadata.
- Customer boundary: tenant hash and deployment hash only.
- Operator boundary: human approval is referenced by approval decision hash, not approval content.

## Evidence Flow

1. Resolve signed release manifest hash.
2. Resolve tenant-scoped deployment context hash.
3. Bind activating node identity hash and authority hash.
4. Create a deployment certificate record.
5. Append the certificate hash into the customer evidence chain.

## Signing Flow

```
release hash + tenant hash + deployment hash
        |
        v
canonical deployment certificate
        |
        v
certificate hash
        |
        v
release/deployment signing authority
```

## Hash-Chain Design

Certificate chain entries should include:

- `previous_deployment_certificate_hash`
- `current_deployment_certificate_hash`
- `release_manifest_hash`
- `policy_bundle_hash`
- `tenant_id_hash`
- `deployment_context_hash`
- `activating_node_hash`

## Customer Isolation Model

The chain must bind each certificate to one tenant hash. A deployment certificate cannot be reused across customers. Validation fails closed if tenant hash, deployment hash, or release hash diverges from the customer evidence chain.

## Rollback Model

Rollback produces a new deployment certificate entry with rollback lineage fields:

- `rollback_from_certificate_hash`
- `rollback_decision_hash`
- `rollback_target_release_hash`
- `rollback_authority_hash`

The original certificate remains immutable.

## Governance Replay Model

Replay proves that deployment activation, rollback, and release continuity match the signed release chain and tenant evidence chain. Missing release signature, stale authority, or unsigned deployment certificate blocks replay.

## Evidence Retention Policy

Deployment certificates inherit the customer evidence retention class and release governance retention class. Certificates remain retained while any regulator export, legal hold, or active deployment depends on them.

## Regulator Export Structure

Export metadata should include certificate IDs, hashes, release lineage summary, policy bundle hash, tenant binding hash, activation timestamp, rollback lineage, and signature verification result.

## 🔍 GAP

Customers need proof that the deployed governance version is the signed, approved release associated with their tenant.

## ⚠️ RISK

If deployment certificates are not chained, a stale or incorrect release could appear valid outside runtime context.

## ✅ MECHANISM

Create signed deployment certificate chain entries that bind release, policy bundle, tenant, node authority, and rollback lineage by hash.

## 🔘 AUDIT

Audit evidence is the deployment certificate hash, previous certificate hash, release manifest hash, policy bundle hash, tenant hash, and signature verification result.

## 👥 IMPACT

Customers and regulators can verify deployment provenance without trusting operator statements or seeing sensitive approval material.
