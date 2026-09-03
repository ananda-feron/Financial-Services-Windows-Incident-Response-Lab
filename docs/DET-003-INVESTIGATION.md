# DET-003 Unexpected-Outcome Investigation

## Finding

The persisted `DET-003` alert on `Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx` is not reproducible with rule version 1.0. The referenced Sysmon Event 10 records `python.exe` accessing `lsass.exe` with `GrantedAccess=0x00001410`; the rule requires `powershell.exe` and exactly `0x00001010`.

The normalized fields match the original XML, so this is not a normalization defect. The source sample's `T1546.003` label also remains reasonable for its primary scenario. The row is therefore classified as an **inconsistent stale detection outcome**, not proof of a false positive and not a missing ground-truth label. Available repository history does not establish how the inconsistent row was originally created.

## Root cause and correction

Alert insertion was idempotent but append-only. Re-evaluating rules inserted current matches without retiring stored outcomes that no longer matched. The engine now reconciles each enabled rule ID/version after evaluation:

- current deterministic alert IDs remain `new`;
- prior rows for the same rule ID/version that are not current matches become `stale`;
- incident correlation and metrics exclude stale rows;
- evidence remains in SQLite for auditability rather than being deleted.

A regression test creates an inconsistent stored result, reruns reconciliation, and verifies that it becomes stale while valid results remain active. This correction returns the current dataset to four active alerts without changing `DET-003` or concealing the historical row.
