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
