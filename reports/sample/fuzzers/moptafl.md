---
title: Moptafl
---

{% capture template %}

<div class="section">
    <h1>Moptafl</h1>
    <p>
        This page shows the distribution of time-to-bug measurements for every bug reached and/or triggered by the
        fuzzer. The results are grouped by library to highlight any performance trends the fuzzer may have against
        specific targets.
    </p>
    
        <h3>poppler</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_poppler_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_poppler_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>libpng</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libpng_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libpng_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>libtiff</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libtiff_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libtiff_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>libxml2</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libxml2_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_libxml2_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>sqlite3</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_sqlite3_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_sqlite3_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>php</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_php_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_php_triggered_box.svg">
                    </div>
                
        </div>
    
        <h3>openssl</h3>
        <div class="row">
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_openssl_reached_box.svg">
                    </div>
                
                    <div class="col s6">
                        <img class="materialboxed responsive-img" src="../plots/moptafl_openssl_triggered_box.svg">
                    </div>
                
        </div>
    
</div>

{% endcapture %}
{{ template | replace: '    ', ''}}
