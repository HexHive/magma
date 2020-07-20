---
title: Bugs
---

{% capture template %}

The following tables list the {{ site.data.bugs | size }} bugs added to Magma, and their corresponding reports.

{% assign targets = site.data.bugs | map: "target" | uniq %}

<table>
<tbody>
{% for target in targets %}
<tr>
<td>
<div class="row">
    {% assign rows = site.data.bugs | where: "target", target %}
    {% assign overflow = rows | size | divided_by: 2 %}
    {% assign left = rows | size | minus: overflow %}
    <div class="row valign-wrapper">
        <div class="col s6">
            <h2><a href="{{ site.github.repository_url }}/tree/master/targets/{{ target }}">{{ site.data.targets[target].display_name }}</a></h2>
        </div>
        <div class="col s6">
            <span class="badge new right" data-badge-caption="bugs">{{ rows | size }}</span>
        </div>
    </div>

    {% if overflow == 0 %}
    <div class="col s12">
    {% else %}
    <div class="col s6">
    {% endif %}
        <table class="highlight">
            <thead>
                <tr>
                    <th>Bug</th>
                    <th>Identifier</th>
                </tr>
            </thead>
            <tbody>
        {% for row in rows limit:left %}
                <tr>
                    <td><a href="{{ site.github.repository_url }}/tree/master/targets/{{ target }}/patches/bugs/{{ row.bug }}.patch">{{ row.bug }}</a></td>
                    <td>{{ row.identifier }}</td>
                </tr>
        {% endfor %}
            </tbody>
        </table>
    </div>

    {% if overflow != 0 %}
    <div class="col s6">
        <table class="highlight">
            <thead>
                <tr>
                    <th>Bug</th>
                    <th>Identifier</th>
                </tr>
            </thead>
            <tbody>
        {% for row in rows offset:left %}
                <tr>
                    <td><a href="{{ site.github.repository_url }}/tree/master/targets/{{ target }}/patches/bugs/{{ row.bug }}.patch">{{ row.bug }}</a></td>
                    <td>{{ row.identifier }}</td>
                </tr>
        {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
</div>
</td>
</tr>
{% endfor %}
</tbody>
</table>

{% endcapture %}
{{ template | replace: '    ', ''}}
