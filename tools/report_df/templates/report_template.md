---
title: {{ report_title }}
---
{% raw %}
{% capture template %}
{% endraw %}
<div class="section">
    <h1>Fuzzed Libraries</h1>
    <p>This report summarizes the results of fuzzing the following libraries:</p>
    <ul id="target-list" class="browser-default">
        {% for (item,num_bugs) in target_list %}
        <li><a href= "libraries/{{item}}.html">{{item}}</a> ({{num_bugs}} bugs)</li>
        {% endfor %}
    </ul>
    <p>
        Total number of forward-ported bugs is {{total_bugs}}, across {{target_list | length}} targets.
    </p>
</div>

<div class="section">
    <h1>Evaluated Fuzzers</h1>
    <p>The fuzzers used in this evaluation are listed below:</p>
    <ul id="fuzzer-list" class="browser-default">
        {% for fuzzer in fuzzer_list %}
        <li><a href= "fuzzers/{{fuzzer}}.html">{{fuzzer}}</a></li>
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
                    This plot shows the mean number of unique bugs triggered by every fuzzer against every target
                    library, and the standard deviation bar, across all campaigns.
                </div>
            </li>
        </ul>
        <img class="materialboxed responsive-img" src ="{{plots_dir}}/mean_variance_bar.svg">
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
        <img class="materialboxed responsive-img" src ="{{plots_dir}}/signplot.svg">
    </div>
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
        <img class="materialboxed responsive-img" src ="{{plots_dir}}/expected_time_to_bug_heat.svg">
    </div>
</div>
{% raw %}
{% endcapture %}
{{ template | replace: '    ', ''}}
{% endraw %}