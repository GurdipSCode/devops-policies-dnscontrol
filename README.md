# 🌐 devops-policies-dnscontrol

![DNSControl](https://img.shields.io/badge/DNSControl-managed-blue?logo=dns)
![OPA](https://img.shields.io/badge/OPA-policy%20as%20code-7C4DFF?logo=openpolicyagent)
![GitOps](https://img.shields.io/badge/GitOps-enabled-success?logo=git)
![CI](https://img.shields.io/badge/CI-validated-informational?logo=githubactions)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Infrastructure-as-Code for **DNS management**, powered by **DNSControl** and protected by **Open Policy Agent (OPA)**.

This repository ensures that **all DNS changes are policy-validated before deployment**, preventing misconfigurations, security risks, and unauthorised record changes.

---

## ✨ Features

✅ Declarative DNS management with **DNSControl**  
✅ Policy-as-Code validation using **OPA (Rego)**  
✅ GitOps-friendly workflow  
✅ CI-ready (pre-commit / pipeline enforcement)  
✅ Prevents insecure, invalid, or non-compliant DNS records  

---

## 🧱 Repository Structure

```text
.
├── dnsconfig.js            # DNSControl configuration
├── creds.json              # Provider credentials (NOT committed)
├── opa/
│   ├── policies/
│   │   └── dnscontrol.rego # OPA policies
│   └── tests/
│       └── dnscontrol_test.rego
├── bundles/
│   └── dnscontrol.tar.gz   # OPA bundle (optional / generated)
├── scripts/
│   ├── validate.ps1
│   └── validate.sh
└── README.md
