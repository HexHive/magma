---
title: {{ fuzzer.name }}
---
{% raw %}
{% capture template %}
{% endraw %}
<div class="section">
    <h1>{{ fuzzer.name }}</h1>
    <p>
        This page shows the distribution of time-to-bug measurements for every bug reached and/or triggered by the
        fuzzer. The results are grouped by library to highlight any performance trends the fuzzer may have against
        specific targets.
    </p>
    {% for library in libraries %}
        <h3>{{ library }}</h3>
        <div class="row">
                {% for metric in reached_triggered %}
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="{{ plot_dir }}/{{ fuzzer.name | lower }}_{{ library | lower}}_{{ metric }}_box.svg">
                    </div>
                {% endfor %}
        </div>
    {% endfor %}
</div>
{% raw %}
{% endcapture %}
{{ template | replace: '    ', ''}}
{% endraw %}