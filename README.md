# Trustless Attestation Verification

## Background
Confidential computing is revolutionizing the way sensitive data is processed and shared in the digital era, enabling applications that were once considered impossible. At its core, Trusted Execution Environments (TEEs) create isolated computational areas protected even from host operating systems and privileged attackers through robust hardware-based safeguards. This innovative technology has been embraced by leading cloud service providers (CSPs) like Google, Microsoft, and AWS, who now offer confidential computing cloud instances for both businesses and individuals with high data privacy requirements.

In this scenario, users with sensitive data—referred to as relying parties throughout this document—send their data to TEE instances hosted by cloud service providers. The TEE then performs computations within the enclave. Before transmitting data, relying parties must ensure that the TEE they are engaging with is in proper condition (e.g., it is a legitimate TEE produced by an authorized hardware vendor and has the latest firmware version). To assist in this verification, the TEE generates various pieces of evidence—such as certificates signed by the hardware vendor, firmware versions, and hash digests of the software stack—that any party can inspect to confirm the TEE's validity. However, this verification process can be burdensome for relying parties, especially if they are typical users without deep expertise in TEEs. Additionally, maintaining the most recent reference values requires significant effort, as relying parties may need to monitor the hardware vendor's updates in real time.

Therefore, Remote Attestation (RA) emerges as a key solution in this scenario. Typically hosted by cloud service providers, the RA service takes responsibility for maintaining reference values and verifying evidence on behalf of the relying parties. This seamless transfer of workload from the relying parties to the service provider creates a more efficient and user-friendly environment for the relying parties.


## Problem Statement
Although the Remote Attestation (RA) service addresses issues on the user side, it introduces a new problem by expanding the trust boundary of the TEE. Ideally, relying parties would only need to trust hardware vendors to correctly implement the TEE. However, they now must also trust the remote attestation service. While this may not be a significant issue most of the time—since RA service providers like cloud service providers are generally trustworthy—corner cases can still occur. For instance, the remote attestation service might become buggy after a version update. Additionally, attackers now have a broader attack surface.

## Our Goal
This project aims to eliminate the need for a trusted third party by utilizing zero-knowledge proofs (ZKP) to create a trustless attestation system. By leveraging zero-knowledge proofs, the attestation service can demonstrate to relying parties that the attestation process is correctly executed. This ensures the integrity of the attestation process, reduces the attack surface, and maintains a minimal trust boundary.

In this particular scenario, we don't actually need the scheme to be zero-knowledge, because the inputs to the remote attestation service—the evidence provided by the TEE—are meant to be transparent and publicly accessible. What we require from zero-knowledge proofs is their ability to demonstrate that the attestation process is executed correctly as expected.

<!-- A general workflow could be as follows: -->


## Implementation
There are numerous Zero-Knowledge Proof (ZKP) schemes and frameworks available for use. This repository serves as the main entry point, with concrete implementations found in the following repositories:

1. Circom-based implementation with Groth16: [link](https://github.com/tiktok-privacy-innovation/trustless-attestation-verification-circom)
   - **Description**: Utilizes Circom circuits and the Groth16 proving system for efficient proof generation and verification.
   - **Features**:
     - Succinct proofs.
     - Efficient verification.
   - **Usage**: Instructions on how to set up and run the implementation can be found in [this repository](https://github.com/tiktok-privacy-innovation/trustless-attestation-verification-circom).


2. RiscZero-based implementation: [link](https://github.com/tiktok-privacy-innovation/trustless-attestation-verification-risczero)
   - **Description**: Employs the Risc0 ZKVM for proof generation and verification.
   - **Features**:
     - Attestation code can be written in Rust, enabling easier implementation and  better auditability.
     - Faster proof generation.
   - **Usage**: Instructions on how to set up and run the implementation can be found in [this repository](https://github.com/tiktok-privacy-innovation/trustless-attestation-verification-risczero).

## License
See the [LICENSE](LICENSE) file for details.

## Contribution
We warmly welcome feedback and contributions from the community. Please feel free to share your valuable comments through GitHub issues or contact us directly!
