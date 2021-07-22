---
title: Bugs
---

{% capture template %}

The following tables list the {{ site.data.bugs | size }} bugs added to Magma, and their corresponding reports.

The following PoC dumps are also available:
<ul class="browser-default">
    <li><a href="https://osf.io/resj8/">2020-10-27</a></li>
    <li><a href="https://drive.switch.ch/index.php/s/Uv1UrEA5ecg9NJk/download">2020-06-27</a></li>
</ul>

{% assign targets = site.data.bugs | map: "target" | uniq %}

<table>
<tbody>
{% for target in targets %}
<tr>
<td>
<div>
    {% assign rows = site.data.bugs | where: "target", target %}
    <div class="row valign-wrapper">
        <div class="col s6">
            <h2><a href="{{ site.github.repository_url }}/tree/master/targets/{{ target }}">{{ site.data.targets[target].display_name }}</a></h2>
        </div>
        <div class="col s6">
            <span class="badge new right" data-badge-caption="bugs">{{ rows | size }}</span>
        </div>
    </div>

    <div class="bugs">
        <table class="highlight">
            <thead>
                <tr>
                    <th>Bug</th>
                    <th>Identifier</th>
                </tr>
            </thead>
            <tbody>
        {% for row in rows %}
                <tr>
                    <td><a target="_blank" href="{{ site.github.repository_url }}/tree/master/targets/{{ target }}/patches/bugs/{{ row.bug }}.patch">{{ row.bug }}</a></td>
                    {% if row.identifier contains "CVE" %}
                        <td><a target="_blank" href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ row.identifier }}">{{ row.identifier }}</a></td>
                    {% else %}
                        <td><a target="_blank" href="{{ row.url }}">{{ row.identifier }}</a></td>
                    {% endif %}
                </tr>
        {% endfor %}
            </tbody>
        </table>
    </div>
</div>
</td>
</tr>
{% endfor %}
</tbody>
</table>

{% endcapture %}
{{ template | replace: '    ', ''}}
