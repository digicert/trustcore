# TrustCore SDK Constitution

## Core Principles

### I. Evidence-Based, Standards-Conformant Engineering

Contributors MUST inspect the relevant code, call sites, and similar implementations before
designing or changing behavior. Decisions MUST be based on verified repository behavior rather
than assumptions. Changes involving cryptographic algorithms or protocols MUST identify the
applicable RFCs, standards, and official specifications, including their versions and relevant
requirements. Implementations and tests MUST follow those requirements. Other changes MUST
consult authoritative documentation and specifications where applicable.

Cryptographic standards conformance is NON-NEGOTIABLE. Code changes MUST NOT compromise
cryptographic strength, entropy, certificate or TLS validation, or secure key handling.
All security-sensitive changes MUST include a brief threat assessment identifying relevant
assets, attacker capabilities, changed trust boundaries, failure modes, and mitigations.
They MUST undergo appropriate security review by reviewers qualified for the affected
cryptographic or protocol behavior before merge.

Rationale: existing behavior establishes integration constraints, while authoritative
specifications establish correctness; neither can safely be inferred from familiarity alone.

### II. Consistent, Focused Implementation

Changes MUST preserve established coding style, naming, error handling, memory management,
and implementation patterns. Contributors MUST reuse suitable existing utilities and limit
changes to the requested behavior and directly dependent call sites. Unrelated refactoring,
speculative abstractions, and unnecessary configuration or infrastructure MUST NOT be added.

When an existing pattern is insufficient, contributors MUST explain the limitation, describe
the proposed alternative and its tradeoffs, and obtain approval from the requester or
responsible maintainer before implementing the deviation.

Rationale: focused, consistent changes make cryptographic code easier to review and reduce
regression risk.

### III. Compatibility and Crypto Interface Boundaries

Changes MUST preserve existing API contracts, cryptographic operations, protocol behavior,
and dependent-component functionality. Any intentional incompatible change MUST be identified
in advance, justified, approved by the responsible maintainer, and accompanied by a migration
or compatibility plan.

New or modified calls into cryptographic implementations MUST go through the crypto interface
instead of directly calling lower-level cryptographic APIs. If the required interface is
missing or insufficient, contributors MUST obtain approval for an interface extension or
alternative under Principle II rather than silently bypassing the boundary. This rule does
not require unrelated rewrites of existing direct calls or prevent the crypto interface
implementation itself from dispatching to its backends.

Rationale: preserving the abstraction boundary keeps algorithm and provider integration
consistent without forcing broad changes to legacy code.

### IV. Feature-Aware, Memory-Safe Cryptography

Changes MUST follow existing feature macros and conditional-compilation patterns and preserve
the relevant enabled and disabled configurations. Contributors MUST identify and verify
affected combinations, including PQC-related configurations where applicable; success in a
single default build MUST NOT be treated as evidence for all configurations.

Any change involving code within the FIPS boundary MUST explicitly state whether it impacts
the validated cryptographic boundary and explain the basis for that assessment. FIPS and
non-FIPS behavior MUST be specified separately and tested. Changes MUST NOT claim that
validation status is preserved without appropriate supporting evidence and security review.

Memory allocation, ownership, error-path cleanup, and release MUST follow existing repository
patterns. Sensitive keys, secrets, and intermediate buffers MUST use the repository's secure
handling and clearing mechanisms as applicable to their lifecycle. Contributors MUST validate
buffer bounds and lengths, prevent arithmetic errors in allocation and copy sizes, and ensure
that success and failure paths do not leak memory, access freed storage, or release resources
more than once.

Rationale: optional features and alternate cryptographic backends exercise distinct paths;
secure ownership and cleanup are correctness requirements in each path.

### V. Meaningful Tests and Regression Evidence

Behavior changes MUST extend existing tests or add focused tests where needed. Tests MUST
cover the introduced or corrected behavior, including applicable success, failure, and
boundary scenarios. Cryptographic changes MUST additionally cover applicable invalid inputs,
signature-verification failures, unsupported algorithms, and interoperability scenarios.
Any omitted applicable category MUST have a documented justification reviewed with the change.

Bug fixes MUST have a reproducible test case before implementation; contributors MUST record
the failing baseline and verify the corrected outcome. Regression testing MUST cover Linux
in both FIPS and non-FIPS modes and Windows in non-FIPS mode. Tests for hangs or potential
deadlocks MUST use explicit, bounded timeouts and fail when the operation does not complete
within the documented limit.

Contributors MUST verify that affected algorithm implementations, protocol functionality,
and dependent components retain their existing behavior. Tests MUST exercise observable
requirements rather than duplicate implementation logic. Redundant cases and unnecessary
test infrastructure MUST NOT be introduced when existing runners and helpers suffice.

Rationale: targeted negative and regression tests establish meaningful confidence without
increasing maintenance cost through redundant infrastructure.

## Engineering Constraints

- The SDK's cross-platform, modular design MUST be preserved. Platform-specific behavior MUST
  use the existing abstractions and remain isolated behind the appropriate configuration.
- C modules MUST remain independently buildable with only their necessary dependencies.
  Changes MUST preserve a minimal footprint and portability across supported compilers and
  platforms; unnecessary dependencies MUST NOT be introduced.
- Supported builds MUST remain reproducible using their documented build commands.
  Windows and Linux build scripts MUST remain consistent and in functional parity for
  shared supported features. Necessary platform-specific differences MUST be documented.
- Patches MUST identify their base tree (repository and revision), expected directory layout
  and application location, and line-ending conventions so that application is reproducible.
- Changes MUST distinguish compile-time algorithm availability from runtime configuration;
  a requested but unavailable algorithm or feature MUST produce an explicit error using
  established error-handling conventions, not a silent fallback.
- Specifications and plans MUST state affected APIs, cryptographic operations, protocol
  versions, feature configurations, memory ownership, and dependent components where relevant.
  Items that do not apply MUST be identified as such rather than left ambiguous.
- Existing contributor and licensing requirements in `CONTRIBUTING.md` and `README.md` remain
  applicable; this constitution does not replace them.

## Development Workflow and Review

1. Inspect relevant implementations and callers; identify applicable official requirements
   and existing build, test, and validation entry points.
2. Define the smallest coherent change and its compatibility, configuration, memory-lifecycle,
   and regression implications. For security-sensitive changes, include a threat assessment;
   for FIPS-boundary changes, document boundary impact and mode-specific behavior. Obtain
   approval for necessary deviations and provide a reproducing test before implementing a fix.
3. Implement using existing patterns and the crypto interface boundary. Add or extend focused
   tests for changed behavior and applicable negative, boundary, and interoperability cases.
4. Run the existing build, tests, and configured lint or formatting checks relevant to the
   change and affected feature combinations, including the required regression platform/mode
   matrix and bounded timeouts for hangs or deadlocks. Verify affected documented build
   commands and shared Windows/Linux build-script parity. Broaden validation when dependencies
   or failures warrant it; documentation-only changes require documentation checks when available.
5. Before merge, provide a review summary stating what changed, why, affected files, tests
   and configurations executed, results, risks, and limitations. Unexecuted checks MUST be
   stated explicitly with the reason; they MUST NOT be represented as passing.

Reviewers MUST verify compliance with each applicable principle, standards requirements,
compatibility expectations, secure cleanup, configuration coverage, and build reproducibility.
Security-sensitive changes MUST receive the security review required by Principle I;
FIPS-boundary changes MUST include the boundary-impact assessment required by Principle IV.
Missing validation or unresolved risks MUST be addressed or explicitly accepted by the responsible maintainer
before merge.

## Governance

This constitution governs project engineering decisions. Project plans, implementation tasks,
and reviews MUST be checked against it. Conflicting local guidance MUST be reconciled with
these principles before the affected work proceeds.

Amendments MUST document the proposed wording, rationale, compatibility implications, and any
required migration or dependent-guidance follow-up. Amendments require responsible-maintainer
review and approval before adoption. Exceptions MUST identify the affected rule, scope,
rationale, risks, and approval; they MUST NOT become undocumented precedent.
Exceptions MUST NOT authorize compromising the non-negotiable cryptographic integrity
requirements in Principle I.

Constitution versions MUST follow semantic versioning: MAJOR for incompatible principle
removals or redefinitions, MINOR for added principles or materially expanded guidance, and
PATCH for non-semantic clarification or corrections. Amendments MUST update the version and
last-amended date, preserve the original ratification date when known, and include a temporary
Sync Impact Report for review. That report MUST be removed before the amendment is committed.

Every feature plan and pull-request review MUST record applicable constitution checks and
explain any approved exception. Governance changes do not authorize unrelated implementation
work.

**Version**: 1.1.1 | **Ratified**: 2026-11-06 | **Last Amended**: 2026-11-06
