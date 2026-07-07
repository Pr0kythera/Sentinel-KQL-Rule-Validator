# Roadmap - Task 7: Sentinel DaC gate improvements

Prioritized proposal for the remaining "critical missing functionality" from
Task 7. Nothing here is implemented yet; this is the proposal to agree on before
building the agreed subset. Each item notes value, effort, and whether it can be
verified on a machine without a .NET runtime.

Legend: [pure] = pure Python, verifiable now. [net] = needs network to vendor
data. [dotnet] = depends on the KQL/Kusto semantic path (needs .NET to verify).

## Priority 1 - high value, mostly verifiable now

1. SARIF output (`--output sarif`). [pure]
   GitHub code scanning consumes SARIF and annotates the exact YAML lines. The
   existing JSON output is a good base. Emit rules/results with file + region
   (line/column) where available so annotations land precisely. High value for a
   PR gate; moderate effort.

2. groupByCustomDetails / groupByEntities consistency. [pure]
   `incidentConfiguration.groupingConfiguration.groupByCustomDetails` must
   reference keys present in `customDetails`; `groupByEntities` must reference
   entity types present in `entityMappings`. The current valid_detection.yaml
   violates this (groups by CommandLine, not a defined custom detail). Concrete,
   cheap, catches real mistakes.

3. Offline mode + asset version reporting. [pure]
   `--offline` fails fast if any vendored asset is missing (ATT&CK bundle, table
   schemas, DLL) so CI never silently degrades. Print the ATT&CK version, table
   schema set version, and Kusto.Language DLL hash/version in every run and in the
   JSON/SARIF output for auditability. Low effort, high determinism payoff.

4. NRT-specific constraints. [pure]
   `kind: NRT` rules differ from Scheduled (NRT does not use queryFrequency/
   queryPeriod the same way and has its own limits). Today the timing logic is
   applied uniformly. Split the timing/threshold rules by kind. Needs a short
   confirmation of the current NRT constraints from Microsoft Learn.

5. alertDetailsOverride column existence and case. [dotnet]
   The `{{Column}}` params in alertDisplayNameFormat / alertDescriptionFormat and
   alertTacticsColumnName / alertSeverityColumnName should reference real output
   columns (reuse the Task 3 extraction and the shared three-way casing check).
   Extends the existing count/whitespace check. Verifiable only where the KQL
   path runs.

## Priority 2 - valuable, more setup

6. JUnit XML output (`--output junit`). [pure]
   For Azure DevOps test reporting. Lower priority than SARIF; similar shape.

7. Query length / cost against the real Sentinel limit. [pure]
   Confirm the current Sentinel query length limit and validate against the real
   value (the existing MAX_QUERY_LENGTH = 10000 is a guess). Warn on obviously
   expensive patterns (already partially done: search / missing TimeGenerated).

8. version / enabled / lastModified hygiene. [pure]
   version semver is already enforced. Add: warn when enabled: true is combined
   with a placeholder/test rule; check lastModified is not in the future.

## Priority 3 - larger, needs external data

9. Data connector / table availability. [net]
   A rule querying a table no connector provides never fires. The Azure-Sentinel
   repo carries connector metadata; vendoring it (pinned, like ATT&CK) would let us
   validate declared `tables:` are backed by an available connector. Largest
   effort; defer unless specifically wanted.

10. Vendored Sentinel table schema set. [net][dotnet]
    Task 3a's ideal source is the Azure-Sentinel KqlvalidationsTests table schema
    JSON (including CustomTables). Vendoring a pinned copy would make the default
    GlobalState far richer than the small bundled schema currently used. Pairs with
    item 9. Needs network to vendor and .NET to verify semantic gains.

## Already delivered outside Task 7

- ATT&CK/DLL/schema load once per process (performance): ATT&CK cached per path,
  DLL loaded once at class level, GlobalState built once per validator instance.
- version semantic-versioning check (pre-existing, retained).

## Suggested first build (recommended subset)

Items 1, 2, 3, 4 (all [pure], high value, verifiable now), plus item 5 wired but
verified later on a .NET machine. Items 6-10 as a follow-up once the core gate is
solid.
