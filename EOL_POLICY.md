# TrustCore SDK End-of-Life (EoL) Policy

**Effective Date:** December 9, 2025  
**Document Version:** 2.0

---

## Overview

This End-of-Life (EoL) policy defines the support lifecycle for TrustCore SDK, including the transition from closed-source proprietary releases to open-source releases under the GNU Affero General Public License v3.0 (AGPL-3.0).

DigiCert is committed to providing clear guidance on product support timelines to help customers plan their technology roadmaps and transitions effectively.

---

## Product Lifecycle Phases

### 1. General Availability (GA)
- **Definition:** The product is fully supported with regular updates, security patches, and technical support.
- **Duration:** Varies by release; typically 24-36 months from GA release date.

### 2. Extended Support
- **Definition:** Critical security updates and limited technical support are provided.
- **Duration:** 12 months following the end of General Availability.

### 3. End-of-Life (EoL)
- **Definition:** No further updates, patches, or technical support are provided.
- **Recommendation:** Customers should migrate to supported versions or the open-source release.

---

## Closed-Source to Open-Source Transition

### Final Closed-Source Release
- **Release:** TrustCore Release GA0521-U8
- **Status:** Final proprietary closed-source release
- **General Availability End Date:** March 31, 2026
- **Extended Support End Date:** March 31, 2027
- **End-of-Life Date:** March 31, 2027

**Support Details for GA0521-U8:**
- Security patches and critical bug fixes until Extended Support ends
- Technical support available through March 31, 2027
- No new features will be added after GA release

### First Open-Source Release
- **Release:** TrustCore Release GA0521-U9
- **License:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Availability:** Q4 2025 (Target)
- **Repository:** [GitHub Repository URL to be announced]

**Open-Source Release Support Model:**
- Community-driven development and support
- Security updates provided through community contributions
- Commercial support options available through DigiCert and partners
- No formal EoL date; support continues as long as community remains active

---

## Support for Legacy Closed-Source Releases

All TrustCore SDK closed-source releases prior to GA0521-U8 are subject to the following timeline:

| Release Version | GA Release Date | GA End Date | Extended Support End | EoL Date |
|----------------|-----------------|-------------|---------------------|----------|
| GA0521-U7 and earlier | Various | December 31, 2025 | December 31, 2026 | December 31, 2026 |
| GA0521-U8 (Final Closed) | Q1 2026 | March 31, 2026 | March 31, 2027 | March 31, 2027 |
| GA0521-U9 (Open-Source) | Q2 2026 | Community-driven | N/A | N/A |

---

## Migration Recommendations

### For Current Closed-Source Users

#### Option 1: Migrate to Open-Source Release (Recommended)
- **Timeline:** Plan migration during Q2-Q3 2026
- **Benefits:**
  - Continued updates and security patches
  - Community-driven innovation
  - No licensing fees for AGPL-compliant Proof of Concept deployments
  - Access to source code for customization
- **Considerations:**
  - Review AGPL-3.0 license requirements for your use case
  - If your application requires proprietary modifications, contact DigiCert for commercial licensing options

#### Option 2: Extended Support for GA0521-U8
- **Timeline:** Available through March 31, 2027
- **Best For:** Organizations requiring additional time for migration planning
- **Limitations:** Security patches only; no new features

#### Option 3: Commercial Support for Open-Source
- **Description:** DigiCert offers commercial support contracts for TrustCore SDK open-source releases
- **Benefits:**
  - SLA-backed support
  - Priority security updates
  - Professional services for migration and integration
  - Custom feature development available
- **Contact:** sales@digicert.com

---

## Dual-License Model for TrustCore SDK

Starting with **TrustCore Release GA0521-U9**, TrustCore SDK is available under a **dual-license model** to accommodate both open-source and commercial use cases.

### Open Source License: GNU Affero General Public License v3 (AGPL v3)

The AGPL v3 license allows you to:
- Use TrustCore SDK for **free** in accordance with AGPL terms
- Modify and distribute the code
- Build applications for personal, educational, or open-source projects

**Key AGPL v3 Requirements:**
1. **Source Code Availability:** If you modify TrustCore SDK and provide it as a network service, you must make your modified source code available to users.
2. **License Compatibility:** Ensure your application's license is compatible with AGPL v3 requirements.
3. **Copyleft Provision:** Derivative works must also be licensed under AGPL v3.

**Full License Text:** See [LICENSE](./LICENSE.md) file or visit https://www.gnu.org/licenses/agpl-3.0.html

### Commercial License: Available via DigiCert Master Services Agreement (MSA)

If you wish to use TrustCore SDK in a **proprietary or commercial product**, a commercial license is required and available under DigiCert's Master Services Agreement (MSA).

**Commercial License is Required For:**
- **Embedded Systems:** Closed-source firmware, IoT devices, embedded hardware products
- **Commercial SaaS Applications:** Providing TrustCore SDK functionality as a service without disclosing source code
- **Proprietary Software Products:** Desktop, mobile, or enterprise applications that do not comply with AGPL v3 terms
- **OEM/VAR Redistribution:** Bundling TrustCore SDK with proprietary commercial products

**Commercial License Benefits:**
- Freedom to use TrustCore SDK in closed-source products
- No obligation to disclose your proprietary source code
- Priority technical support and SLA guarantees
- Custom feature development and professional services
- Indemnification and warranty protections
- Flexible licensing terms tailored to your business needs

**Contact for Commercial Licensing:**
- **Email:** sales@digicert.com
- **Subject Line:** "TrustCore SDK Commercial License Inquiry"
- **Website:** https://github.com/digicert/trustcore

---

## Choosing the Right License

| Use Case | Recommended License | Details |
|----------|-------------------|---------|
| Open-source projects | AGPL v3 (Free) | Fully compliant with open-source distribution |
| Proof of Concept / Evaluation | AGPL v3 (Free) | No cost for non-production testing |
| Educational / Research | AGPL v3 (Free) | Ideal for academic and research purposes |
| Commercial Products (Closed-Source) | Commercial License | Required for proprietary firmware, SaaS, embedded systems |
| IoT/Embedded Devices | Commercial License | Required when source code cannot be disclosed |
| Enterprise SaaS Platforms | Commercial License | Required unless you make all source code available under AGPL v3 |
| Mobile/Desktop Apps (Proprietary) | Commercial License | Required for closed-source distribution |

**Important:** Using TrustCore SDK in a commercial product without a commercial license is a violation of the AGPL v3 terms and DigiCert's intellectual property rights. Please contact sales@digicert.com to discuss your licensing needs.

---

## Security Updates and Vulnerability Disclosure

For comprehensive security policies, vulnerability reporting procedures, and responsible disclosure guidelines, please refer to our **[Security Policy](https://github.com/digicert/trustcore/blob/main/SECURITY.md)**.

### Closed-Source Releases (GA0521-U8 and earlier)
- Security vulnerabilities will be addressed according to severity:
  - **Critical:** Patch within 14 days
  - **High:** Patch within 30 days
  - **Medium/Low:** Evaluated on a case-by-case basis during Extended Support period
- **Report vulnerabilities to:** support@digicert.com

### Open-Source Releases (GA0521-U9 and later)
- **Reporting Channel:** Use [GitHub Security Advisories](https://github.com/digicert/trustcore/security/advisories) for private vulnerability disclosure
- **Alternative Contact:** security@digicert.com (PGP encryption encouraged for sensitive reports)
- **Response Timeline:**
  - Initial acknowledgment within 48 hours
  - Severity assessment within 5 business days
  - Security patches following coordinated disclosure practices
- **Coordinated Disclosure:** We work with security researchers to coordinate public disclosure after patches are available
- **Security Updates:** Critical security patches will be backported to supported releases when feasible

**Please do NOT report security vulnerabilities through public GitHub issues.** Use the private reporting channels above to ensure responsible disclosure and protect TrustCore SDK users.

---

## Technical Support

### Closed-Source Support Channels
- **Email:** trustcore-support@digicert.com
- **Support Portal:** https://support.digicert.com
- **Phone:** Available for customers with active support contracts

### Open-Source Support Channels
- **GitHub Issues:** Primary support channel for bug reports and feature requests
- **GitHub Discussions:** Community Q&A and general discussions
- **Documentation:** https://docs.trustcore.digicert.com
- **Commercial Support:** trustcore-sales@digicert.com

---

## Frequently Asked Questions

### Q: Will my existing closed-source license continue to work after EoL?
**A:** Yes, your license remains valid. However, you will not receive updates or support after the EoL date. We recommend migrating to the open-source release or purchasing extended support.

### Q: Can I continue using GA0521-U8 after March 31, 2027?
**A:** Yes, but without security updates or technical support. This is not recommended for production environments.

### Q: What are the key differences between closed and open-source releases?
**A:** Feature parity is maintained. The primary difference is the license model (proprietary vs. AGPL-3.0) and support model (commercial vs. community-driven with commercial options).

### Q: Do I need to open-source my application if I use TrustCore SDK GA0521-U9?
**A:** Under AGPL v3, if you distribute modified versions of TrustCore SDK or provide it as a network service, you must make your source code available. For commercial products (embedded systems, proprietary firmware, closed-source SaaS), you **must obtain a commercial license** from DigiCert. Contact sales@digicert.com for licensing details.

### Q: Can I use TrustCore SDK for free in my commercial product?
**A:** No. While AGPL v3 allows free use for open-source projects, **commercial use in proprietary products requires a commercial license** under DigiCert's Master Services Agreement (MSA). This includes embedded systems, IoT devices, closed-source firmware, and commercial SaaS applications.

### Q: What happens if I use TrustCore SDK commercially without a license?
**A:** Using TrustCore SDK in a commercial product without a proper commercial license violates AGPL v3 terms and constitutes intellectual property infringement. DigiCert reserves the right to pursue legal remedies. Please contact sales@digicert.com to obtain proper licensing.

### Q: How do I obtain a commercial license for TrustCore SDK?
**A:** Contact DigiCert sales at sales@digicert.com with details about your use case. Our licensing team will work with you to create a tailored commercial license agreement under DigiCert's Master Services Agreement (MSA).

### Q: Will there be breaking changes between GA0521-U8 and GA0521-U9?
**A:** We aim to maintain API compatibility. Any breaking changes will be clearly documented in the migration guide.

### Q: Is there a trial period for commercial licensing?
**A:** Yes, you can evaluate TrustCore SDK under AGPL v3 for proof-of-concept and non-production testing. For production commercial use, a commercial license is required.

---

## Contact Information

- **General Inquiries:** trustcore@digicert.com
- **Sales & Licensing:** trustcore-sales@digicert.com
- **Technical Support:** trustcore-support@digicert.com
- **Security Issues:** security@digicert.com
- **Documentation:** https://docs.trustcore.digicert.com
- **GitHub Repository:** [To be announced with GA0521-U9 release]

---

## Policy Updates

This EoL policy may be updated periodically. Customers will be notified of material changes via:
- Email notifications to registered support contacts
- Updates on https://www.digicert.com/legal-repository
- Announcements in GitHub repository (for open-source releases)

**Last Updated:** December 9, 2025  
**Previous Version:** [DigiCert EoL/EoS Policies v2.0](https://www.digicert.com/legal-repository/eol-eos-policies)

---

© 2025 DigiCert, Inc. All rights reserved. TrustCore is a trademark of DigiCert, Inc.
