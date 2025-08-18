---
layout: page
title: Tools & Projects
---

# Open Source Security Tools

{% for tool in site.data.tools %}
## [{{ tool.name }}]({{ tool.url }})
{{ tool.description }}

**Tags:** {% for tag in tool.tags %}{{ tag }}{% unless forloop.last %}, {% endunless %}{% endfor %}

---
{% endfor %}

# Project Contributions

{% for project in site.data.projects %}
## [{{ project.name }}]({{ project.url }})
{{ project.description }}

**Role:** {{ project.role }}  
**Tags:** {% for tag in project.tags %}{{ tag }}{% unless forloop.last %}, {% endunless %}{% endfor %}

---
{% endfor %}
