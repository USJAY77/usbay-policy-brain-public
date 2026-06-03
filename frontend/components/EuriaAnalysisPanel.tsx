export type EuriaAnalysisPanelProps = {
  recommendation: "BLOCKED" | "HUMAN_REVIEW";
  missingEvidence: string[];
  unsupportedClaims: string[];
  privacyRisks: string[];
  confidenceSummary: string;
};

export function EuriaAnalysisPanel({
  recommendation,
  missingEvidence,
  unsupportedClaims,
  privacyRisks,
  confidenceSummary,
}: EuriaAnalysisPanelProps) {
  return (
    <section aria-labelledby="euria-analysis-title" data-authority="analysis-only">
      <h2 id="euria-analysis-title">Euria Analysis Panel</h2>
      <p>Euria analyzes evidence only. Euria cannot approve, execute, modify policy, bypass review, or override USBAY.</p>
      <dl>
        <dt>Euria Recommendation</dt>
        <dd>{recommendation}</dd>
        <dt>Missing Evidence</dt>
        <dd>{missingEvidence.length ? missingEvidence.join(", ") : "none"}</dd>
        <dt>Unsupported Claims</dt>
        <dd>{unsupportedClaims.length ? unsupportedClaims.join(", ") : "none"}</dd>
        <dt>Privacy Risks</dt>
        <dd>{privacyRisks.length ? privacyRisks.join(", ") : "none"}</dd>
        <dt>Confidence Summary</dt>
        <dd>{confidenceSummary}</dd>
      </dl>
    </section>
  );
}
