{% extends base_template %}
{% block title -%}
{{ report_title }}
{%- endblock %}

{% block body %}
<div class="section">
    <h1>Experiment Configuration</h1>
    <ul class="browser-default">
        <li><b>Duration</b>: {{ duration }}</li>
        <li><b>Trials</b>: {{ trials }}</li>
        <li><b>Version</b>: {{ version }}</li>
    </ul>
</div>
<div class="section">
    <h1>Fuzz Targets</h1>
    <p>This report summarizes the results of fuzzing the following targets:</p>
    <ul id="target-list" class="browser-default">
        {% for target in target_list %}
        <li><a href="targets/{{ target }}.html">{{ target }}</a></li>
        {% endfor %}
    </ul>
</div>

<div class="section">
    <h1>Evaluated Fuzzers</h1>
    <p>The fuzzers used in this evaluation are listed below:</p>
    <ul id="fuzzer-list" class="browser-default">
        {% for fuzzer in fuzzer_list %}
        <li><a href="fuzzers/{{ fuzzer }}.html">{{ fuzzer }}</a></li>
        {% endfor %}
    </ul>
</div>

<!--
EXPERIMENT PARAMETERS WILL BE LISTED HERE
-->

<div class="section">
    <h1>Experiment Summary</h1>
    <div id="bugs-triggered">
        <h2>Total Unique Bugs Triggered</h2>
        <ul class="collapsible popout">
            <li>
                <div class="collapsible-header">
                    <h3>Mean and Standard Deviation</h3>
                </div>
                <div class="collapsible-body">
                    This plot shows the mean number of unique bugs triggered by every fuzzer against every target,
                    and the standard deviation bar, across all campaigns.
                </div>
            </li>
        </ul>
        <img class="materialboxed responsive-img" src="{{ uniq_bugs }}">
        <ul class="collapsible popout">
            <li>
                <div class="collapsible-header">
                    <h3>Stastistical Significance</h3>
                </div>
                <div class="collapsible-body">
                    This matrix summarizes the p-values of the pairwise Mann-Whitney U tests calculated against the
                    total bug count sample sets collected for every fuzzer across all campaigns. Cells with a green
                    shade indicate that the number of bugs triggered by a fuzzer is statistically different.
                </div>
            </li>
        </ul>
        <img class="materialboxed responsive-img" src="{{ sigmatrix }}">
    </div>
{#
    <div id="expected-ttb">
        <h2>Expected Time-to-Bug</h2>
        <ul class="collapsible popout">
            <li>
                <div class="collapsible-header">
                    <h3>Ranking of Bugs and Fuzzers</h3>
                </div>
                <div class="collapsible-body">
                    This table shows the calculated values of expected time-to-trigger-bug for every bug triggered
                    during the evaluation. The calculation accounts for missed measurements (where the fuzzer only
                    triggers a bug in M out of N campaigns) and fits the distribution of time-to-bug samples onto an
                    exponential distribution. More information about this can be found in the Magma paper.
                </div>
            </li>
        </ul>
        <img class="materialboxed responsive-img" src="{{ ett }}">
    </div>
#}
    <div id="mean-survival">
        <h2>Mean Survival Time</h2>
        <ul class="collapsible popout">
            <li>
                <div class="collapsible-header">
                    <h3>Ranking of Bugs and Fuzzers</h3>
                </div>
                <div class="collapsible-body">
                    This table shows the restricted mean survival time for every bug being reached or triggered over the
                    duration of the campaign, using the Kaplan-Meier non-parametric survival function estimator.
                    Green-shaded cells indicate the best performance (lowest time) for a bug metric across all fuzzers.
                    Yellow-shaded cells indicate the worst performance (highest time) for a bug metric across all fuzzers.
                    Red-shaded cells indicate that the bug survived being reached or triggered by the fuzzer throughout
                    the campaign duration.
                </div>
            </li>
        </ul>
        <div class="center">
            <a id="btn-colormap" class="btn-small waves-effect waves-light" style="margin-bottom: 10px; color: white; font-weight: normal;">
                <i class="material-icons left">color_lens</i>
                Change Colormap
            </a>
        </div>
        <script type="text/javascript">
            $('#btn-colormap').click(function() {
                stl = $('#survival_stylesheet');
                var href = stl.prop('href');
                if (href.includes('hiliter')) {
                    stl.prop('href', '{{ heatmap_css }}');
                } else {
                    stl.prop('href', '{{ hiliter_css }}');
                }
            });
        </script>
        <link id="survival_stylesheet" rel="stylesheet" href="{{ hiliter_css }}">
        {% include survtable %}
    </div>
</div>
{% endblock %}