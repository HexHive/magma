{% extends base_template %}
{% block title -%}
{{ fuzzer }}
{%- endblock %}

{% block body %}
<div class="section">
    <h1>{{ fuzzer }}</h1>
    <p>
        This page shows the distribution of time-to-bug measurements for every bug reached and/or triggered by the
        fuzzer. The results are grouped by target to highlight any performance trends the fuzzer may have against
        specific targets.
    </p>
{% for target in plots.index.get_level_values(0).unique()%}
    {% set target_p = plots.xs(target) %}
    <h2>{{ target }}</h2>
    {% for program in target_p.index.get_level_values(0).unique() %}
        {% set program_p = target_p.xs(program) %}
        <h3>{{ program }}</h3>
        <div class="row">
        {% for metric in program_p.index.get_level_values(0).unique() %}
            {% set metric_p = program_p.xs(metric) %}
            <div class="col s6">
                <img class="materialboxed responsive-img" src="../{{ metric_p }}">
            </div>
        {% endfor %}
        </div>
    {% endfor %}
{% endfor%}
</div>
{% endblock %}