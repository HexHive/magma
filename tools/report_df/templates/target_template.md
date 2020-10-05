{% extends base_template %}
{% block title -%}
{{ target }}
{%- endblock %}

{% block body %}
<div class="section">
    <h1>{{ target }}</h1>
    <p>
        This page displays the aggregate information about the target as collected from the evaluation.
    </p>
{#
    <div class="card-panel amber lighten-5">
        <div class="row valign-wrapper" style="margin-bottom: 0;">
            <div class="col s2 m1 center-align">
                <i class="small material-icons">warning</i>
            </div>
            <div class="col s10 m11">
                <span class="black-text">
                    This page is incomplete. In a future update, per-bug information will be added.
                </span>
            </div>
        </div>
    </div>
#}
    <div class="row">
        <div class="col s8 offset-s2">
            <img style="display: block; margin: auto;" src="../{{ legend }}">
        </div>
    </div>
{% for program in plots.index.get_level_values(0).unique() %}
    {% set program_p = plots.xs(program) %}
    <h2>{{ program }}</h2>
    {% for bug in program_p.index.get_level_values(0).unique() %}
        {% set bug_p = program_p.xs(bug) %}
    <h3>{{ bug }}</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../{{ bug_p }}">
        </div>
    </div>
    {% endfor %}
{% endfor %}
</div>
{% endblock %}