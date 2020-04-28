<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th>CVE ID</th>
      <th>Vulnerability Type</th>
      <th>Ported</th>
      <th>Component</th>
      <th>Bug ID</th>
      <th>Report</th>
      <th>Fix</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>CVE-2019-9020</td>
      <td>Out of bound read or read after free</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE001</td>
      <td>Secadv  <a href="https://security.netapp.com/advisory/ntap-20190321-0001/">link</a></td>
      <td>Fix <a href="https://bugs.php.net/bug.php?id=77242">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9021</td>
      <td>Heap buffer over-read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE002</td>
      <td>Git <a href="<a href="https://bugs.php.net/bug.php?id=77247">link</a>">link</a> Trigger <a href="<a href="https://bugs.php.net/bug.php?id=77247">link</a>">link</a></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9023</td>
      <td>Heap buffer over-read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td></td>
      <td>Git <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/mbstring/oniguruma/regparse.c;h=252ca187120238a77055ca51b40f7e5f14250d9c;hp=d2925f1e81b0bb827db02b260cca1058355135d2;hb=20407d06ca3cb5eeb10f876a812b40c381574bcc;hpb=a918020c03880e12ac9f38e11a4a3789491a5f85,Git">link</a> <a href="http://git.php.net/?p=php-src.git;a=commit;h=9d6c59eeea88a3e9d7039cb4fed5126ef704593a,Git">link</a> <a href="http://git.php.net/?p=php-src.git;a=commitdiff;h=28362ed4fae6969b5a8878591a5a06eadf114e03;hp=20407d06ca3cb5eeb10f876a812b40c381574bcc">link</a></td>
      <td></td>
      <td>ext/mbstring/oniguruma folder not present anymore.</td>
    </tr>
    <tr>
      <td>CVE-2019-9025</td>
      <td>Buffer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE003</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77381">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/mbstring/php_mbregex.c;h=85219b00e4f0300fce747f42f363608adce01fd4;hp=68922b696653af386a8b5faca06ff99d66e0f75a;hb=e617f03066ce81d26f56c06d6bd7787c7de08703;hpb=e40027ef0f508be87b323f61532cea0104212b53">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9641</td>
      <td>Uninitialized read (only in 32bit builds)</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE004</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77509">link</a></td>
      <td>Fix <a href="https://bugs.php.net/bug.php?id=77509">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-6977</td>
      <td>Heap buffer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE005</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77270">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/gd/libgd/gd_color.c;h=e6f539bc75b5520001fbad71fda977d7c5fdd96c;hp=a4e56b1c40157b7f9334967bcd101f63a47f919b;hb=7a12dad4dd6c370835b13afae214b240082c7538;hpb=1cc2182bcc81e185c14837e659d12b268cb99d63">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9675</td>
      <td>Buffer overflow (practical attack is usally impossible)</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td><a href="https://www.php.net/ChangeLog-7.php">link</a></td>
    </tr>
    <tr>
      <td>CVE-2019-11041</td>
      <td>Buffer over-read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE006</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=78222">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=aa272c1d2b2df09593f7d2b98b46f4c64f2f0bfb;hp=e04290376ce57cdcc1c7e1dfad9f323d8cfb98bb;hb=f22101c8308669bb63c03a73a2cac2408d844f38;hpb=d561a998c9313749ad2b488685e5c2bec661bc69">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11042</td>
      <td>Buffer over-read can lead to crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE007</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=78256">link</a></td>
      <td>Fix <a href="https://bugs.php.net/bug.php?id=78256">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11034</td>
      <td>Buffer over-read can lead to crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE008</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=78256">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=0b5bb5ae2123989a28b2112ab5506777083ad9d5;hp=fe89b854711879274555bdc762ea6e7fa518fa59;hb=f3aefc6d071b807ddacae0a0bc49f09c38e18490;hpb=0ecac37c40a27ffbd59f34b5920735ee0b7f994c">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11035</td>
      <td>buffer over-read can lead to crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11036</td>
      <td>Heap buffer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td></td>
      <td></td>
      <td></td>
      <td>File has changed since then.</td>
    </tr>
    <tr>
      <td>CVE-2019-11039</td>
      <td>Out of bound read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE009</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77950">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/iconv/iconv.c;h=b4a2abe08d9a02e9e6c07f51a8f4ebe895f0d003;hp=f86d0ae031987a12d45b9c10efc255f58262966b;hb=7cf7148a8f8f4f55fb04de2a517d740bb6253eac;hpb=ed6dee9a198c904ad5e03113e58a2d2c200f5184">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11040</td>
      <td>Heap buffer overflow, out of bound read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE010</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77950">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=605b37923f888d320a87947a58f19fd2122475e8;hp=d174def80c1355fc54d09a0ae754ced64d85768d;hb=73ff4193be24192c894dc0502d06e2b2db35eefb;hpb=16e037bd46359a31f218ee220ff09f1c3270e489">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2017-7189</td>
      <td>Security issue</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>Bug report marked as private.</td>
    </tr>
    <tr>
      <td>CVE-2018-20783</td>
      <td>Read out of bound</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE011</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77143">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/phar/phar.c;h=47ff8cd790730dbc3520e47faa86327e2987a238;hp=780be432570e80dd34c1a9c217ef87ade22bf136;hb=48f0f73f75c0059ba5d9b73cb4e5faeeaea49c47;hpb=7edc639b9ff1c3576773d79d016abbeed1f93846">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9022</td>
      <td>Read out of bound</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE012</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77369">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=commitdiff;h=8d3dfabef459fe7815e8ea2fd68753fd17859d7b;hp=31f59e1f3074ab344b473dde6077a6844ca87264">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9024</td>
      <td>Read out of bound</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE013</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77380">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/xmlrpc/libxmlrpc/base64.c;h=a4fa19327b76dc43880934bfd703500aeae35c52;hp=5ebdf31f7adeb9fd5f9f69b37d86ce22e4d05ce4;hb=1cc2182bcc81e185c14837e659d12b268cb99d63;hpb=28362ed4fae6969b5a8878591a5a06eadf114e03">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9637</td>
      <td>File is briefly accessible with the wrong permissions</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>??? Not sure how to find trigger condition in system.</td>
    </tr>
    <tr>
      <td>CVE-2019-9638</td>
      <td>Uninitialized read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE014</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77563">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=fe89b854711879274555bdc762ea6e7fa518fa59;hp=ea88a8f115e8a366f5f7419a01b1acf58260d420;hb=8ac6fee8562533a15db90062117210ed28b44fea;hpb=5f0e62a3e5b525163e538aaab0161c2c8c5d057b">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-9639</td>
      <td>Uninitialized read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td></td>
      <td></td>
      <td></td>
      <td>In the same patch as bugMAE014 but somehow the fix isn't there anymore.</td>
    </tr>
    <tr>
      <td>CVE-2019-9640</td>
      <td>Invalid read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE015</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=77540">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=ea88a8f115e8a366f5f7419a01b1acf58260d420;hp=b4563927a5058e93ad55074fe367e4bac0ef987e;hb=5f0e62a3e5b525163e538aaab0161c2c8c5d057b;hpb=5e824a88d073d282c4f358f186cb87ddc284f83d">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-11038</td>
      <td></td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>Bug in graphical extension.</td>
    </tr>
    <tr>
      <td>CVE-2018-19935</td>
      <td>Null ptr deref and crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Code not present anymore.</td>
    </tr>
    <tr>
      <td>CVE-2018-19396</td>
      <td>Null pointer dereference and application crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>??? Not sure how to find trigger condition in system.</td>
    </tr>
    <tr>
      <td>CVE-2018-19395</td>
      <td></td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>??? Not sure how to find trigger condition in system.</td>
    </tr>
    <tr>
      <td>CVE-2018-17082</td>
      <td></td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>Bug in component Apache2.</td>
    </tr>
    <tr>
      <td>CVE-2018-14883</td>
      <td>Heap-based buffer over-read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE016</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=76423">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/exif/exif.c;h=1147980f7730de0dfd13904a2ea6461bbf4eded8;hp=e535278fc9664f5b7e5ddcdb6baec07426b8efd6;hb=1baeae42703f9b2ec21fff787146eeca08d45535;hpb=fe3d53f4437718fad63850695970dddd63144af5">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2018-7584</td>
      <td>Stack-based buffer under-read</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE017</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=75981">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/standard/http_fopen_wrapper.c;h=75d21c0761658cf32ac8960eb47bd9ec1d2cfa52;hp=f6b0368d4ef423efbc366b29214f1f69e8ad3878;hb=7cf491b661ee57a11b79f99416c6296bae2f27a0;hpb=8354a831031167c715898a8af09a2a743784ab6b">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2017-9120</td>
      <td>Buffer overflow and application crash</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Fix isn't even in the code.</td>
    </tr>
    <tr>
      <td>CVE-2017-11362</td>
      <td>Stack-based buffer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE018</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=74603">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=commitdiff;h=95c4564f939c916538579ef63602a3cd31941c51;hp=9c5717d0decd56710129a5599fe5d38f82a7bab2">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2014-9912</td>
      <td>Buffer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE019</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=67397">link</a></td>
      <td>Fix <a href="http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/intl/locale/locale_methods.c;h=0597182bdc69ea3c089fb269d8be7758d2daa57d;hp=8eb663cb167d6044f6051a3e2fd9952c3c213982;hb=2a29add9e41cf98eb516be6bafd66a13cb42b9b3;hpb=5ecee6ebce576142fd13d2d1ec0bd52dac3086f9">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2016-10159</td>
      <td>Integer overflow</td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE020</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=73764">link</a></td>
      <td>Fix <a href="https://github.com/php/php-src/commit/ca46d0acbce55019b970fcd4c1e8a10edfdded93">link</a></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2016-7414</td>
      <td></td>
      <td><p style="text-align: center;">&#10007;</p></td>
      <td>ext</td>
      <td>MAE021</td>
      <td>Trigger <a href="https://bugs.php.net/bug.php?id=72928">link</a></td>
      <td>Fix <a href="https://github.com/php/php-src/commit/0bfb970f43acd1e81d11be1154805f86655f15d5?w=1">link</a></td>
      <td></td>
    </tr>
  </tbody>
</table>