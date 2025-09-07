---
title: Tools & Projects
icon: fas fa-tools
order: 5
---

## Tools

<div class="tools-grid">
{% for tool in site.data.tools %}
  <div class="tool-card">
    <h3><a href="{{ tool.url }}" target="_blank" rel="noopener noreferrer">{{ tool.name }}</a></h3>
    <p>{{ tool.description }}</p>
    <p class="tool-language"><i class="fas fa-tags"></i> {{ tool.tags | join: ', ' }}</p>
  </div>
{% endfor %}
</div>

## Other Contributions

<div class="projects-grid">
{% for project in site.data.projects %}
  <div class="project-card">
    <h3><a href="{{ project.url }}" target="_blank" rel="noopener noreferrer">{{ project.name }}</a></h3>
    <p>{{ project.description }}</p>
    <p class="project-role"><i class="fas fa-user-tag"></i> {{ project.role }}</p>
  </div>
{% endfor %}
</div>

<style>
.tools-grid, .projects-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 20px;
  margin-bottom: 30px;
}

.tool-card, .project-card {
  border: 1px solid var(--btn-border-color);
  border-radius: 8px;
  padding: 15px;
  background-color: var(--card-bg);
  transition: transform 0.2s;
}

.tool-card:hover, .project-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.tool-card h3, .project-card h3 {
  margin-top: 0;
  margin-bottom: 10px;
}

.tool-card p, .project-card p {
  margin: 10px 0;
}

.tool-language, .project-role {
  font-size: 14px;
  color: var(--text-muted-color);
}
</style>
