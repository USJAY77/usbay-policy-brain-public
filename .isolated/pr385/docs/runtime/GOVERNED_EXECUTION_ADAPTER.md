# Governed Execution Adapter Contract

PB-1D defines a metadata-only adapter boundary. It does not call providers, open sockets, spawn subprocesses, load SDKs, or execute production actions.

The implementation lives at `runtime/computer_use/execution_adapter_contract.py`, matching the governed runtime source allow-list.

An adapter result may be `ALLOWED` only after all governance prechecks are true: policy evaluation, human approval, execution contract, capability, target policy, dependency readiness, runtime readiness, replay protection, nonce, timestamp, parameters, and evidence destination.

Any missing, malformed, unsupported, timeout, exception, incompatible, unavailable, or blocked adapter state returns `BLOCKED` with deterministic hash-only evidence. Mock adapters exist only to validate the contract.
