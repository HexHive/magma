---
title: {% block title %}## UNIMPLEMENTED ##{% endblock %}
---
{# The `raw` blocks allow Jekyll to re-template the output correctly. #}
{% raw %}
{% capture template %}
{% endraw %}

{% block body %}
{% endblock %}

{% raw %}
{% endcapture %}
{{ template | replace: '    ', ''}}
{% endraw %}
