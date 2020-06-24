---
title: Troubleshoot
---

In this section, we highlight some common problems users may face when running
Magma or integrating with it. Make sure to check out the
[FAQ]({{"/docs/faq.html"|absolute_url}}) section in case your question is
answered there.

{% capture template %}

<ul class="collapsible questions">
{% for item in site.data.troubleshoot %}
  <li>
    <div class="collapsible-header">
      <i class="material-icons drop-down"></i>
{{ item.question }}
    </div>
    <div class="collapsible-body">
{{ item.answer }}
    </div>
  </li>
{% endfor %}
</ul>

{% endcapture %}
{{ template | replace: '    ', ''}}
