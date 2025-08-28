---
title: Talks & Presentations
icon: fas fa-microphone
order: 6
---

<div class="talks-grid">
{% for talk in site.data.talks %}
  <div class="talk-card">
    <h3>{% if talk.url %}<a href="{{ talk.url }}" target="_blank" rel="noopener noreferrer">{{ talk.title }}</a>{% else %}{{ talk.title }}{% endif %}</h3>
    <p class="talk-event"><strong>{{ talk.event }}</strong></p>
    <p class="talk-location">📍 {{ talk.location }} • {{ talk.date | date: "%B %Y" }}</p>
    {% if talk.description %}<p class="talk-description">{{ talk.description }}</p>{% endif %}
    {% if talk.speakers %}<p class="talk-speakers"><strong>Speaker(s):</strong> {{ talk.speakers }}</p>{% endif %}
    {% if talk.role %}<p class="talk-role"><strong>Role:</strong> {{ talk.role }}</p>{% endif %}
    <div class="talk-links">
      {% if talk.slides %}<a href="{{ talk.slides }}" target="_blank" rel="noopener noreferrer" class="talk-link">📄 Slides</a>{% endif %}
      {% if talk.video %}<a href="{{ talk.video }}" target="_blank" rel="noopener noreferrer" class="talk-link">🎥 Video</a>{% endif %}
    </div>
  </div>
{% endfor %}
</div>

<style>
.talks-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 25px;
  margin-top: 25px;
}

.talk-card {
  border: 1px solid var(--btn-border-color);
  border-radius: 10px;
  padding: 20px;
  background-color: var(--card-bg);
  transition: transform 0.2s, box-shadow 0.2s;
}

.talk-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 12px rgba(0,0,0,0.15);
}

.talk-card h3 {
  margin-top: 0;
  margin-bottom: 15px;
  color: var(--link-color);
}

.talk-event {
  margin: 10px 0;
  font-size: 16px;
  font-weight: 600;
}

.talk-location {
  margin: 8px 0;
  font-size: 14px;
  color: var(--text-muted-color);
}


.talk-description {
  margin: 15px 0;
  font-size: 14px;
  line-height: 1.6;
}

.talk-speakers, .talk-role {
  margin: 8px 0;
  font-size: 14px;
  color: var(--text-muted-color);
}

.talk-links {
  margin-top: 15px;
  display: flex;
  gap: 15px;
}

.talk-link {
  display: inline-block;
  padding: 6px 12px;
  border: 1px solid var(--btn-border-color);
  border-radius: 5px;
  text-decoration: none;
  font-size: 14px;
  transition: all 0.2s;
}

.talk-link:hover {
  background-color: var(--btn-hover-bg);
  transform: translateY(-1px);
}
</style>