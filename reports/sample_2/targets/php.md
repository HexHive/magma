---
title: php
---


{% capture template %}



<div class="section">
    <h1>php</h1>
    <p>
        This page displays the aggregate information about the target as collected from the evaluation.
    </p>

    <div class="row">
        <div class="col s8 offset-s2">
            <img style="display: block; margin: auto;" src="../plot/survival_legend.svg">
        </div>
    </div>

    
    <h2>exif</h2>
    
        
    <h3>MAE004</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../plot/survival_php_exif_MAE004.svg">
        </div>
    </div>
    
        
    <h3>MAE006</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../plot/survival_php_exif_MAE006.svg">
        </div>
    </div>
    
        
    <h3>MAE008</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../plot/survival_php_exif_MAE008.svg">
        </div>
    </div>
    
        
    <h3>MAE014</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../plot/survival_php_exif_MAE014.svg">
        </div>
    </div>
    
        
    <h3>MAE016</h3>
    <div class="row">
        <div class="col s8 offset-s2">
            <img class="materialboxed responsive-img" src="../plot/survival_php_exif_MAE016.svg">
        </div>
    </div>
    

</div>



{% endcapture %}
{{ template | replace: '    ', ''}}
