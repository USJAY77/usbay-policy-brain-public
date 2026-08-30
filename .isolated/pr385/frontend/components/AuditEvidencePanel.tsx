export type AuditEvidencePanelProps = {
  auditRecordId: string;
  signatureStatus: "SIGNATURE_METADATA_PRESENT" | "SIGNED" | "BLOCKED";
  timestampStatus: "TIMESTAMP_PENDING_EXPORT" | "TIMESTAMPED" | "BLOCKED";
  auditChainStatus: "COMPLETE" | "BLOCKED";
  latestEventHash: string;
};

export function AuditEvidencePanel({
  auditRecordId,
  signatureStatus,
  timestampStatus,
  auditChainStatus,
  latestEventHash,
}: AuditEvidencePanelProps) {
  return (
    <section aria-labelledby="audit-evidence-title" data-authority="usbay-audit-authority">
      <h2 id="audit-evidence-title">Audit Evidence Panel</h2>
      <p>Audit status reflects USBAY evidence only. Unknown, missing, or incomplete evidence remains blocked.</p>
      <dl>
        <dt>Audit Record ID</dt>
        <dd>{auditRecordId}</dd>
        <dt>Signature Status</dt>
        <dd>{signatureStatus}</dd>
        <dt>Timestamp Status</dt>
        <dd>{timestampStatus}</dd>
        <dt>Audit Chain Status</dt>
        <dd>{auditChainStatus}</dd>
        <dt>Latest Event Hash</dt>
        <dd>{latestEventHash}</dd>
      </dl>
    </section>
  );
}
