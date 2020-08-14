---
title: Php
---

{% capture template %}

<div class="section">
	<h1>Php</h1>
    <p>
        This page displays the aggregate information about the library as collected from the evaluation.
    </p>
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
    <h2>Total Bugs Reached and Triggered</h2>
	<img class="materialboxed responsive-img" src="../plots/php_reached_and_triggered_bar.svg" >
</div>

{% endcapture %}
{{ template | replace: '    ', ''}}
