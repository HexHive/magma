---
title: {{ library.name }}
---
{% raw %}
{% capture template %}
{% endraw %}
<a href={{ library.link }}>repository</a>

<div class="targets">
    <span>
        In table bellow you will find all the implemented bugs in the {{library_name}} library.
    </span>

    <h2>Benchmark Results</h2>
    <div>
      <img src="{{ plots_dir }}/{{ library.name | lower }}_unique_bug_line_plot.svg" alt="">
      <img src="{{ plots_dir }}/{{ library.name | lower }}_reached_and_triggered_bar.svg" >
    </div>
    <div>
          <img src="{{ plots_dir }}/{{ library.name | lower }}_mean_variance_bar.svg" >
    </div>
</div>
{% raw %}
{% endcapture %}
{{ template | replace: '    ', ''}}
{% endraw %}