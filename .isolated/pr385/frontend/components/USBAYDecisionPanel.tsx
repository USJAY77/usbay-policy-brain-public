export type USBAYDecisionPanelProps = {
  decision: "APPROVED" | "HUMAN REVIEW" | "BLOCKED";
  policyBrainOutput: "APPROVED" | "HUMAN REVIEW" | "BLOCKED";
  blockedScenarios: string[];
  approvedScenario: string;
};

export function USBAYDecisionPanel({
  decision,
  policyBrainOutput,
  blockedScenarios,
  approvedScenario,
}: USBAYDecisionPanelProps) {
  return (
    <section aria-labelledby="usbay-decision-title" data-authority="enforcement-authority">
      <h2 id="usbay-decision-title">USBAY Decision Panel</h2>
      <p>USBAY Policy Brain is the only demo enforcement authority shown in this workflow.</p>
      <dl>
        <dt>USBAY Decision</dt>
        <dd>{decision}</dd>
        <dt>Policy Brain Output</dt>
        <dd>{policyBrainOutput}</dd>
        <dt>Blocked Scenarios</dt>
        <dd>{blockedScenarios.join(", ")}</dd>
        <dt>Approved Scenario</dt>
        <dd>{approvedScenario}</dd>
      </dl>
    </section>
  );
}
