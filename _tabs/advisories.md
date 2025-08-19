---
title: Security Research
icon: fas fa-shield-alt
order: 4
---

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
    <h3>{{ advisory.id }}</h3>
    <p><strong>Vendor:</strong> {{ advisory.vendor }}</p>
    <p><strong>Product:</strong> {{ advisory.product }}</p>
    <p><strong>Type:</strong> {{ advisory.type }}</p>
    <p><strong>Year:</strong> {{ advisory.year }}</p>
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