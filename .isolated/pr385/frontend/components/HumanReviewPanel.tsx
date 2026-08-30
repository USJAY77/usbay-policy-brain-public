export type HumanReviewPanelProps = {
  approvalStatus: "APPROVED" | "REQUIRED" | "BLOCKED";
  reviewerDecision: "APPROVED" | "PASS" | "REVIEW_REQUIRED" | "BLOCKED" | "FAIL";
  reviewRequired: boolean;
  bypassAllowed: false;
};

export function HumanReviewPanel({
  approvalStatus,
  reviewerDecision,
  reviewRequired,
  bypassAllowed,
}: HumanReviewPanelProps) {
  return (
    <section aria-labelledby="human-review-title" data-authority="human-approval-required">
      <h2 id="human-review-title">Human Review Panel</h2>
      <p>High-risk governance outcomes require documented human review. Review bypass is never allowed.</p>
      <dl>
        <dt>Human Approval Status</dt>
        <dd>{approvalStatus}</dd>
        <dt>Reviewer Decision</dt>
        <dd>{reviewerDecision}</dd>
        <dt>Review Required</dt>
        <dd>{reviewRequired ? "true" : "false"}</dd>
        <dt>Bypass Allowed</dt>
        <dd>{bypassAllowed ? "true" : "false"}</dd>
      </dl>
    </section>
  );
}
