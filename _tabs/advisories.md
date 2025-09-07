---
title: Security Research
icon: fas fa-shield-alt
order: 4
---

## Research Collaboration

I'm interested in exchanging knowledge with fellow security researchers working on:
- Industrial protocol analysis and reverse engineering
- Vulnerability research in ICS/OT systems
- Development of open-source security tools
- Novel attack vectors in critical infrastructure

To discuss **public research** or anything else, feel free to reach out via LinkedIn or any of my social accounts. 

## Disclaimer

All security research is conducted in my personal capacity, following responsible disclosure practices and applicable laws. Views and research expressed here are my own and do not represent any employer or organization. I do not offer commercial security services or consulting.

## CVE Discoveries

Below is a list of CVE (Common Vulnerabilities and Exposures) discoveries I've made in industrial control systems and OT products.

<div class="cve-grid">
{% for cve in site.data.cves %}
  <div class="cve-card">
    <h3><a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank" rel="noopener noreferrer">{{ cve.id }}</a></h3>
    <p><strong>Vendor:</strong> {{ cve.vendor }}</p>
    <p><strong>Product:</strong> {{ cve.product }}</p>
    <p><strong>Type:</strong> {{ cve.type }}</p>
    <p><strong>Year:</strong> {{ cve.year }}</p>
  </div>
{% endfor %}
</div>

## Other Security Advisories

<div class="cve-grid">
{% for advisory in site.data.advisories %}
  <div class="cve-card">
    <h3>{% if advisory.link %}<a href="{{ advisory.link }}" target="_blank" rel="noopener noreferrer">{{ advisory.id }}</a>{% else %}{{ advisory.id }}{% endif %}</h3>
    <p><strong>Vendor:</strong> {{ advisory.vendor }}</p>
    <p><strong>Product:</strong> {{ advisory.product }}</p>
    <p><strong>Type:</strong> {{ advisory.type }}</p>
    {% if advisory.cvss %}<p><strong>CVSS:</strong> {{ advisory.cvss }}</p>{% endif %}
    {% if advisory.severity %}<p><strong>Severity:</strong> {{ advisory.severity }}</p>{% endif %}
    {% if advisory.description %}<p><strong>Description:</strong> {{ advisory.description }}</p>{% endif %}
    <p><strong>Year:</strong> {{ advisory.year }}</p>
  </div>
{% endfor %}
</div>

## MITRE ATT&CK Contributions

Contributing to the MITRE ATT&CK framework for ICS by documenting real-world adversary techniques and tactics.

<div class="cve-grid">
{% for technique in site.data.mitre_attack %}
  <div class="cve-card">
    <h3><a href="{{ technique.url }}" target="_blank" rel="noopener noreferrer">{{ technique.id }} - {{ technique.title }}</a></h3>
    <p><strong>Tactic:</strong> {{ technique.tactic }}</p>
    <p><strong>Description:</strong> {{ technique.description }}</p>
    {% if technique.reference %}<p><strong>Reference:</strong> {{ technique.reference }}</p>{% endif %}
    {% if technique.platforms %}<p><strong>Platforms:</strong> {{ technique.platforms }}</p>{% endif %}
  </div>
{% endfor %}
</div>

<style>
.cve-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 20px;
}

.cve-card {
  border: 1px solid var(--btn-border-color);
  border-radius: 8px;
  padding: 15px;
  background-color: var(--card-bg);
  transition: transform 0.2s;
}

.cve-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.cve-card h3 {
  margin-top: 0;
  margin-bottom: 10px;
}

.cve-card p {
  margin: 5px 0;
  font-size: 14px;
}
</style>