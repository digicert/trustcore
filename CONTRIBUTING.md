# Contributor Guidelines

These guidelines summarize the repository's contribution workflow and engineering expectations. Follow the [README contribution steps](README.md), use the affected module's build and test instructions in [GUIDE.md](GUIDE.md), and consult the [TrustCore SDK constitution](.specify/memory/constitution.md) for the full requirements.

## Workflow and implementation

- Inspect the relevant code, callers, tests, and existing patterns before changing behavior. For cryptographic or protocol changes, identify the applicable standards and versions.
- Keep changes focused. Reuse repository helpers and follow established naming, error-handling, memory-management, and modular design patterns. Keep platform-specific behavior behind existing abstractions. Preserve API and protocol compatibility; get maintainer approval for deviations or incompatible changes.
- Route new or modified cryptographic calls through the crypto interface. If it is insufficient, ask for approval before extending or bypassing that boundary.

## Secure development

- Validate untrusted inputs; sanitize user input where appropriate to its format and use. Check lengths, bounds, and allocation arithmetic. Do not hardcode secrets. Follow existing ownership and cleanup patterns, and securely clear sensitive key material when its lifecycle requires it.
- For security-sensitive changes, briefly assess affected assets, attacker capabilities, trust boundaries, failure modes, and mitigations. Arrange review by maintainers qualified for the affected cryptographic or protocol behavior.
- Identify affected feature configurations and verify the relevant enabled and disabled paths. For changes within the FIPS boundary, state the impact and test FIPS and non-FIPS behavior as applicable. Do not claim that validation status is preserved without supporting evidence and review.

## Tests, coverage, and review

- For behavior changes, add or extend focused unit tests for applicable success, failure, and boundary cases. Cryptographic tests should also cover applicable invalid inputs, verification failures, unsupported algorithms, and interoperability. Bug fixes should include a reproducible regression test.
- Run the affected module's documented tests and relevant configurations. The constitution's regression matrix is Linux in FIPS and non-FIPS modes, plus Windows in non-FIPS mode; explain any applicable checks that could not be run.
- When available, report line, function, and branch coverage for the affected test suite and link to its CI run or coverage artifact. Coverage is suite-specific; do not infer a project-wide threshold. If coverage data is unavailable, say so.
- In the pull request, summarize the change, affected files, tests and configurations run, results, risks, limitations, and checks not run with the reason. Documentation-only changes need appropriate documentation checks, not software unit tests.

---

# Contributor License Agreement (CLA)

Thank you for your interest in contributing to the TrustCore and TrustEdge projects!

To protect the legal interests of DigiCert and our users, contributors must agree to the following terms before we can accept any code contributions.

## Terms

By submitting a pull request or contribution to this project, you agree that:

1. **You are the author of the contribution**, or you have the necessary rights and permissions to make the contribution on behalf of yourself or your organization.

2. **You grant DigiCert, Inc. and its affiliates** a perpetual, worldwide, royalty-free, non-exclusive license to use, reproduce, modify, adapt, sublicense, and distribute your contribution:
   - As part of the open-source project under the AGPL v3 license, and
   - As part of DigiCert’s proprietary and commercial offerings under separate commercial license terms.

3. **You agree** that your contribution may be dual-licensed by DigiCert under both:
   - The GNU Affero General Public License v3 (https://www.gnu.org/licenses/agpl-3.0.html), and
   - DigiCert’s commercial licensing terms (e.g., https://www.digicert.com/master-services-agreement/, as updated from time to time).

4. If you are contributing on behalf of a company, you represent that you are authorized to submit the contribution and bind the company to these terms. 

5. You acknowledge that this agreement **applies to all contributions**, past and future, submitted to this project unless you notify us otherwise in writing. 

## Why This Matters

This agreement ensures:
- We maintain clean intellectual property rights over the project.
- We can continue to dual-license the project to support both open-source and commercial users. 
- You (the contributor) are clearly acknowledged and protected under open source norms. 

We may use a tool to enforce acceptance of this agreement when pull requests are submitted. 

If you have questions about this agreement, please contact us at opensourcelegal@digicert.com. 

Thank you for helping us build secure and trusted open-source software! 

*This agreement is adapted from the Apache Software Foundation and Google Individual Contributor License Agreements.* 