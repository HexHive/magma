---
title: {{ fuzzer.name }}
---
{% raw %}
{% capture template %}
{% endraw %}
<div>
  <h6>
    Description of fuzzer:
  </h6>
  <ul id="target_list">
      <li>{{ fuzzer.type }}</li>
      <li>{{ fuzzer.use_case }}</li>
      <li>{{ fuzzer.availability }}</li>
      <li><a href="{{ fuzzer.link }}">site</a></li>
  </ul>
</div>
<div id="some_id" class="some_class">
  {% for library in libraries %}
  <h3>
    {{ library }}
  </h3>
    {% for choice in choices %}
      {% for reached in reached_triggered %}
    <img src="{{ plot_dir }}/{{ fuzzer.name|lower }}_{{ library |lower}}_{{ reached }}_{{ choice }}.svg" alt="">
      {% endfor %}
    {% endfor %}
  {% endfor %}
</div>
{% raw %}
{% endcapture %}
{{ template | replace: '    ', ''}}
{% endraw %}