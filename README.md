# TrustCore SDK

**TrustCore SDK** is a cross-platform security toolkit built for developers. It is entirely written in C and includes a quantum-safe cryptographic (PQC) library, TLS 1.3 stack, and clients for MQTT, EST, SCEP, SSH, RADIUS, EAP and others. TrustCore SDK is compact, performant and modular, designed for secure connected devices. 

> [!NOTE]
> DigiCert is in the process of completely open-sourcing the code under the AGPL v3 license to support transparency, collaboration, and developer accessibility, while maintaining commercial licensing for commercial and proprietary use. Code will be open-sourced on a per-module basis and progress on which modules have been released can be tracked in the related [Github Project](https://github.com/orgs/digicert/projects/31). 

## TrustCore SDK Overview  

TrustCore SDK is a powerful suite of security tools hardend over 15 years of usage, designed to simplify and enhance certificate-based authentication, encryption, and secure communications. Previously a closed-source solution, it is now being open-sourced to empower developers with greater flexibility in integrating robust security mechanisms into their applications.  

### **Key Capabilities**

- **Certificate Lifecycle Management** – Supports enrollment, renewal, revocation, and validation.  
- **PKI Integration** – Seamless interaction with public key infrastructure for secure identity verification.  
- **Broad Cryptographic Algorithm Support** – From message digests to symmetric and asymmetric algorithms, TrustCore [NanoCrypto](https://dev.digicert.com/en/trustcore-sdk/nanocrypto.html) has you covered.  
- **Trusted Platform Integration** – Enables integration with TPMs and hardware security modules (HSMs).  
- **EST & CMP Protocol Support** – Implements industry-standard protocols for certificate provisioning and management.
- **Secure Device Communications** - Delivers MQTT (MQTTs) over TLS 1.3 for securing device communications.
- **PQC-ready** - Utilize the latest post-quantum cryptographic algorithms including: ML-KEM, ML-DSA and SLH-DSA, ensuring your devices are quantum-safe.
- **Modular and compact** - Each module is implemented in lightweight C code. Build only the required modules to minimize the device footprint.
- **FIPS 140-3 ready** - Need FIPS 140-3 certification? No problem! Contact us to learn more how we can help you certify your product.
- **OpenSSL Interop** - Provides a compatibility layer for applications using OpenSSL APIs, enabling seamless integration.

### **Supported Protocols and How to Build**

TrustCore SDK provides comprehensive support for various security and communication protocols, ensuring secure interactions across different applications and environments:

- [NanoSSH](https://dev.digicert.com/en/trustcore-sdk/nanossh.html) – Secure Shell (SSH) client and server implementation optimized for lightweight environments, learn to [compile here](https://dev.digicert.com/en/trustcore-sdk/nanossh/nanossh-client-user-guide/nanossh-client-overview.html#generate-nanossh-client-quick-build).

- [NanoMQTT](https://dev.digicert.com/en/trustcore-sdk/nanomqtt.html) - Secure MQTT (Message Queuing Telemetry Transport) client for IoT and cloud communications.

- [NanoSSL](https://dev.digicert.com/en/trustcore-sdk/nanossl.html) - Implementation for SSL/TLS 1.3, providing secure transport layer encryption.

- [NanoSec](https://dev.digicert.com/en/trustcore-sdk/nanosec.html) – Strong encryption and security for network layer communications using IPSec/IKE..

- [NanoEAP]() – Extensible Authentication Protocol (EAP) for secure network authentication and RADIUS support.

- [NanoCert](https://dev.digicert.com/en/trustcore-sdk/nanocert.html) – EST and SCEP Protocols for automated certificate enrollment and management.

### **Documentation**

All the TrustCore documentation is available at [TrustCore SDK documentation](https://dev.digicert.com/en/trustcore-sdk.html).  

## License

This project is available under a **dual-license model**:

- **Open Source License:**  
  [GNU Affero General Public License v3 (AGPL v3)](./LICENSE.md)
  This license allows you to use, modify, and distribute the code for free in accordance with AGPL terms.

- **Commercial License:**  
If you wish to use TrustCore SDK in a **proprietary** or **commercial** product (e.g., embedded in closed-source firmware or commercial SaaS applications), a commercial license is available under DigiCert’s [Master Services Agreement](https://www.digicert.com/master-services-agreement/) (MSA).  Contact us at [sales@digicert.com](mailto:sales@digicert.com) for commercial licensing details.

## Contributing

We welcome contributions that improve TrustCore SDK! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commits
4. Submit a pull request
5. Review and accept the [Contributor License Agreement (CLA)](CONTRIBUTING.md)

## Contributor License Agreement (CLA)

All contributors must agree to a **Contributor License Agreement (CLA)** before we can accept your pull request. By submitting a pull request, you agree to the terms of the CLA.

By contributing, you agree that DigiCert may license your contributions under both:

- AGPL v3 (open source), and
- DigiCert’s commercial licensing terms

To learn more, see [CONTRIBUTING.md](CONTRIBUTING.md). We may use an integrated tool to enforce CLA acceptance during the pull request process.

## Legal and Compliance Notes

- This project uses a **copyleft license (AGPL v3)**. If you include this code in a larger application, you may be required to release the source of that application under AGPL.
- If you are unsure whether your intended use triggers AGPL obligations, please reach out to [legal@digicert.com](mailto:opensourcelegal@digicert.com) for clarification or [sales@digicert.com](mailto:sales@digicert.com) for commercial options.

## Reporting a Vulnerability

We encourage responsible disclosure of security vulnerabilities.
If you find something suspicious, we encourage and appreciate your report! To learn more, see [SECURITY.md](SECURITY.md).

## Contact

- Commercial licensing: [sales@digicert.com](mailto:sales@digicert.com)
- General inquiries: [support@digicert.com](mailto:support@digicert.com)

---

(c) 2025 DigiCert, Inc. All rights reserved.
