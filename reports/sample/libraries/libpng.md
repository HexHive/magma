---
title: Libpng
---

{% capture template %}

<a href="https://github.com/glennrp/libpng">repository</a>

<div class="targets">
    <span>
        In table bellow you will find all the implemented bugs in the  library.
    </span>

    <h2>Benchmark Results</h2>
    <div>
      <img src="../plots/libpng_reached_and_triggered_bar.svg" >
    </div>
</div>

{% endcapture %}
{{ template | replace: '    ', ''}}
