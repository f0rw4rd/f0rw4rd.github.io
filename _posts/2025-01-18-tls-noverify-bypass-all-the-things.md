---
title: "TLS NoVerify: Bypass All The Things"
date: 2025-08-18 00:00:00 +0100
author: f0rw4rd
categories: [Tools, Security Research]
tags: [tls, ld-preload, pentesting, reverse-engineering]
description: "Learn how to bypass TLS certificate validation on Linux using LD_PRELOAD for security research and debugging of embedded systems and native applications"
image:
  path: /assets/img/tlsnoverify_badssl.png
  alt: "BadSSL dashboard showing bypassed certificate validation"
pin: true
---

> **🚀 Get the tool:** [github.com/f0rw4rd/tls-preloader](https://github.com/f0rw4rd/tls-preloader)
> 
> A universal TLS certificate bypass tool supporting OpenSSL, GnuTLS, NSS, mbedTLS, and wolfSSL - all with a single LD_PRELOAD!
{: .prompt-info }

When conducting security research on embedded devices and industrial applications, researchers frequently encounter a common obstacle: TLS certificate validation. Many embedded applications are built using OpenSSL or similar libraries with properly implemented certificate verification. While this is excellent from a security perspective, it presents challenges during legitimate research activities when attempting to analyze network traffic.

![Raccoon just wants the data](https://i.imgflip.com/a3g3pv.jpg){: w="500" }
_Just trying to get the data from embedded devices_

The typical scenario involves receiving `CERTIFICATE_VERIFY_FAILED` errors when attempting to intercept and analyze application traffic. This occurs because the application correctly validates the certificate chain and rejects any certificates that don't match its expectations.

Traditional approaches to this problem include:
- **Binary patching** - Requires deep knowledge of the specific TLS library implementation and some time
- **Dynamic instrumentation (Frida)** - Powerful but requires writing JavaScript hooks for each target application and library, also Frida does not work well with musl libc user spaces
- **Certificate infrastructure setup** - Time-consuming process of creating CA certificates, and some embedded systems have read-only CA files 
- **Source code modification** - Only viable when source code is available, which is rarely the case for proprietary applications

## Solution: Dynamic Library Interposition with LD_PRELOAD

The [**tls-preloader**](https://github.com/f0rw4rd/tls-preloader) tool provides an elegant solution to this problem by leveraging the `LD_PRELOAD` mechanism available on Linux and Unix systems. This approach allows dynamic interception of library function calls without modifying the target application or its libraries.

### Technical Implementation

```bash
LD_PRELOAD=/tmp/libtlsnoverify.so your_app
```

The tool works by interposing certificate verification functions and returning success values, effectively bypassing validation checks. This approach eliminates the need for binary patching, recompilation, or complex certificate infrastructure.

### Supported TLS Libraries

The tool supports multiple TLS implementations commonly found in embedded and industrial applications:

- **OpenSSL/BoringSSL** - The most widely deployed TLS library
- **GnuTLS** - GNU Transport Layer Security library
- **NSS** - Network Security Services (Mozilla)
- **mbedTLS** - Lightweight TLS implementation for embedded systems
- **wolfSSL** - Embedded SSL/TLS library
- **libcurl** - HTTP library with built-in certificate validation 

## Practical Applications

The tool has several legitimate use cases in security research and development:

- **Security assessments** - Analyzing network traffic during penetration testing engagements
- **Legacy application debugging** - Troubleshooting industrial control systems and SCADA applications
- **IoT device analysis** - Intercepting communications from embedded devices for security evaluation
- **Development and testing** - Simplifying certificate management in test environments

## Installation

```bash
git clone https://github.com/f0rw4rd/tls-preloader
cd tls-preloader
make
LD_PRELOAD=./libtlsnoverify.so curl https://expired.badssl.com
```

### Technical Details: Intercepted Functions

The tool intercepts the following certificate verification functions:
- **OpenSSL**: `SSL_CTX_set_verify`, `X509_verify_cert`, and related validation functions
- **GnuTLS**: `gnutls_certificate_verify_peers2`, `gnutls_certificate_verify_peers3`
- **NSS**: `CERT_VerifyCertificate` and related NSS verification APIs
- **curl**: `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_SSL_VERIFYHOST` options
- Additional library-specific verification functions

### Known Limitations

The tool has several limitations that users should be aware of:

- **Statically linked applications** - Cannot intercept functions in statically linked binaries
- **Rust applications using rustls** - The rustls library is typically statically linked
- **Go programs** - Go's native TLS implementation is not based on dynamic libraries
- **Chrome/Chromium** - Ships with a bundled, statically linked BoringSSL implementation 
- **High Level Language** - C# and Java have high level implementations or some high level checks that can not be overloaded

## Example Commands

```bash
# Basic usage - just make it work
LD_PRELOAD=/tmp/libtlsnoverify.so wget https://self-signed.badssl.com

# Debug mode - see what's being bypassed
TLS_NOVERIFY_DEBUG=1 LD_PRELOAD=/tmp/libtlsnoverify.so curl https://expired.badssl.com

# Backtrace mode - for when you really want to know what's happening
TLS_NOVERIFY_BACKTRACE=1 LD_PRELOAD=/tmp/libtlsnoverify.so curl https://expired.badssl.com

# The "let's break Firefox" special
TLS_NOVERIFY_BACKTRACE=1 LD_PRELOAD=/tmp/libtlsnoverify.so firefox https://badssl.com/dashboard/
```

## Get Started with tls-preloader

Ready to bypass TLS validation for your security research? Check out the full source code and documentation:

> **[→ github.com/f0rw4rd/tls-preloader](https://github.com/f0rw4rd/tls-preloader)**
{: .prompt-tip }

### Case Study: Firefox and BadSSL.com

The following example demonstrates the tool's effectiveness when used with Firefox browser accessing the BadSSL.com test suite:

```bash
$ TLS_NOVERIFY_BACKTRACE=1 LD_PRELOAD=/tmp/libtlsnoverify.so firefox https://badssl.com/dashboard/
```

![Launch with call stack dump](/assets/img/tlsnoverify_firefox.png)

The backtrace shows the tool successfully intercepting Firefox's NSS library calls. Each certificate validation attempt is logged and bypassed.

![BadSSL Dashboard with all certificates accepted](/assets/img/tlsnoverify_badssl.png)

The BadSSL.com dashboard, which is designed to test certificate validation, shows all test cases in red - indicating that the browser successfully connected to hosts with bad certificates. This is the expected behavior when using tls-preloader, as it bypasses all certificate validation checks. The tool effectively disables protection against expired certificates, self-signed certificates, hostname mismatches, and other TLS security issues that BadSSL.com tests for.

---