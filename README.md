### Fork

This project combines two major forks:

* [dunderhay/git-rotate](https://github.com/dunderhay/git-rotate)
* [mandatoryprogrammer/thermoptic](https://github.com/mandatoryprogrammer/thermoptic)

### Stealth Fingerprint Multilayer Spoofing

A research-focused tool designed for security testing, capable of simulating multiple fingerprint layers to match Chrome/Chromium behavior. It also performs IP rotation every 5 requests.

Supports:

* IP Rotation (via GitHub Actions)
* JA4 (TLS fingerprint)
* JA4H (HTTP fingerprint)
* JA4X (X509 certificate fingerprint)
* JA4T (TCP fingerprint)
* New (`--disable-blink-features=AutomationControlled`) to bypass WebDriver Detection

### Overview
<img width="897" height="590" alt="image" src="https://github.com/user-attachments/assets/34bf7a76-d99d-4a00-9a10-3324f8c3027c" />

### Adjustments

You can adapt `catcher-microsoft-login.py` or `catcher-fingerprint.py` to customize how requests are crafted during **security research and detection-evasion testing**. These adjustments are useful for evaluating how infrastructures respond when multiple fingerprint layers and IP validation mechanisms are in place—for example, when assessing defenses against scenarios such as password spraying, brute-force attempts, or MFA validation abuse.

### Demo
We can note different IP Addresses and the same JA4 hash (impersonating chrome):
<img width="1420" height="744" alt="image" src="https://github.com/user-attachments/assets/02a603ff-c5ae-4f4a-9e1f-47aef3a3b915" />
