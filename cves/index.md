---
layout: page
title: CVE Discoveries
---

# Vulnerability Research

{{ site.data.cves.size }} CVEs discovered across ICS/OT systems, medical devices, and enterprise software.

{% for cve in site.data.cves %}
## {{ cve.id }}
**Date:** {{ cve.date }}  
**Severity:** {{ cve.severity }}  
**Product:** {{ cve.product }}  
**Description:** {{ cve.description }}

---
{% endfor %}
