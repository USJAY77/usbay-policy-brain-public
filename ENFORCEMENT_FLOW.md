USBAY Enforcement Decision Flow

1. AI / system requests action execution
2. Request enters USBAY enforcement gateway
3. Policy evaluation engine evaluates rules
4. If approval required:
      - approval request created
      - execution paused
5. Upon approval decision:
      - decision recorded in audit log
6. Enforcement engine executes:
      - allow / deny / review
7. Execution outcome logged to decision record
