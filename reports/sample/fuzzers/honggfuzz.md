---
title: HonggFuzz
---

{% capture template %}

<div>
  <h6>
    Description of fuzzer:
  </h6>
  <ul id="target_list">
      <li>Gray-box binary fuzzer</li>
      <li>Mutational fuzzing</li>
      <li>Open-source</li>
      <li><a href="https://honggfuzz.dev">site</a></li>
  </ul>
</div>
<div id="some_id" class="some_class">
  
  <h3>
    poppler
  </h3>
    
      
    <img src="../plots/honggfuzz_poppler_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_poppler_triggered_box.svg" alt="">
      
    
  
  <h3>
    libpng
  </h3>
    
      
    <img src="../plots/honggfuzz_libpng_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_libpng_triggered_box.svg" alt="">
      
    
  
  <h3>
    libtiff
  </h3>
    
      
    <img src="../plots/honggfuzz_libtiff_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_libtiff_triggered_box.svg" alt="">
      
    
  
  <h3>
    libxml2
  </h3>
    
      
    <img src="../plots/honggfuzz_libxml2_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_libxml2_triggered_box.svg" alt="">
      
    
  
  <h3>
    sqlite3
  </h3>
    
      
    <img src="../plots/honggfuzz_sqlite3_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_sqlite3_triggered_box.svg" alt="">
      
    
  
  <h3>
    php
  </h3>
    
      
    <img src="../plots/honggfuzz_php_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_php_triggered_box.svg" alt="">
      
    
  
  <h3>
    openssl
  </h3>
    
      
    <img src="../plots/honggfuzz_openssl_reached_box.svg" alt="">
      
    <img src="../plots/honggfuzz_openssl_triggered_box.svg" alt="">
      
    
  
</div>

{% endcapture %}
{{ template | replace: '    ', ''}}
