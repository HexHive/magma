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
      <td>CVE-2019-14494</td>
      <td>Divide-by-zero</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH042</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/802">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/b224e2f5739fe61de9fa69955d016725b2a4b78d">link</a></td>
      <td>pdftoppm.</td>
    </tr>
    <tr>
      <td>CVE-2019-9959</td>
      <td>Resource exhaustion (memory)</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH043</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/805">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/68ef84e5968a4249c2162b839ca6d7975048a557">link</a></td>
      <td>pdftoppm. Discovered by fuzzing pdftocairo.</td>
    </tr>
    <tr>
      <td>CVE-2019-9631</td>
      <td>Heap buffer overflow</td>
      <td>False</td>
      <td>poppler</td>
      <td>AAH044</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/736">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/merge_requests/206/diffs">link</a></td>
      <td>Might not be reproducible since it needs a specific version of cairo.</td>
    </tr>
    <tr>
      <td>CVE-2018-20662</td>
      <td>Sigabrt</td>
      <td>False</td>
      <td>pdfunite</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/706">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/mkasik/poppler/commit/7b4e372deeb716eb3fe3a54b31ed41af759224f9">link</a></td>
      <td>Not a core bug.</td>
    </tr>
    <tr>
      <td>CVE-2018-18897</td>
      <td>Memory leak</td>
      <td>False</td>
      <td>poppler</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/654">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/e07c8b4784234383cb5ddcf1133ea91a772506e2">link</a></td>
      <td>Memory is not "leaked" uncontrollably. A single object is left to be released by the OS. Also, could be app-specific.</td>
    </tr>
    <tr>
      <td>CVE-2017-9865</td>
      <td>Stack buffer overflow</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH045</td>
      <td>Report <a href="https://bugs.freedesktop.org/show_bug.cgi?id=100774">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/75fff6556eaf0ef3a6fcdef2c2229d0b6d1c58d9">link</a></td>
      <td>pdfimages.</td>
    </tr>
    <tr>
      <td>CVE-2019-10873</td>
      <td>0-pointer dereference</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH046</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/748">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/8dbe2e6c480405dab9347075cf4be626f90f1d05">link</a></td>
      <td>pdftoppm. Discovered by fuzz project pwd-poppler-pdftoppm-03</td>
    </tr>
    <tr>
      <td>CVE-2019-10871</td>
      <td>Heap buffer overread</td>
      <td>False</td>
      <td>poppler</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/751">link</a></td>
      <td></td>
      <td>Bug report still not resolved.</td>
    </tr>
    <tr>
      <td>CVE-2019-12293</td>
      <td>Heap buffer overread</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH047</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/768">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/89a5367d49b2556a2635dbb6d48d6a6b182a2c6c">link</a></td>
      <td>pdftoppm. Discovered by fuzzing pdftotext.</td>
    </tr>
    <tr>
      <td>CVE-2019-10872</td>
      <td>Heap buffer overflow</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH048</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/750.">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/6a1580e84f492b5671d23be98192267bb73de250">link</a></td>
      <td>pdftoppm -mono. Discovered by fuzz project pwd-poppler-pdftoppm-00</td>
    </tr>
    <tr>
      <td>CVE-2019-9903</td>
      <td>Stack overflow - recursion</td>
      <td>False</td>
      <td>poppler</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/741">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/fada09a2ccc11a3a1d308e810f1336d8df6011fd">link</a></td>
      <td>I don't like this.</td>
    </tr>
    <tr>
      <td>CVE-2019-11026</td>
      <td>Stack overflow</td>
      <td>False</td>
      <td>poppler</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/752">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/8051f678b3b43326e5fdfd7c03f39de21059f426">link</a></td>
      <td>I don't like this.</td>
    </tr>
    <tr>
      <td>CVE-2019-9200</td>
      <td>Heap buffer underwrite</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH049</td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/728">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/f4136a6353162db249f63ddb0f20611622ab61b4">link</a></td>
      <td>pdfimages.</td>
    </tr>
    <tr>
      <td>CVE-2018-20551</td>
      <td>Sigabrt</td>
      <td>False</td>
      <td>poppler</td>
      <td></td>
      <td>Report <a href="https://gitlab.freedesktop.org/poppler/poppler/issues/703">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/7f87dc10b6adccd6d1b977a28b064add254aa2da">link</a></td>
      <td>I don't like this.</td>
    </tr>
    <tr>
      <td>Bug #106061</td>
      <td>Divide-by-zero</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH050</td>
      <td>Report <a href="https://bugs.freedesktop.org/show_bug.cgi?id=106061">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/88c99f1f6f4faf31faabccd35d9d094958020ebc">link</a></td>
      <td>pdfimages or pdftoppm</td>
    </tr>
    <tr>
      <td>ossfuzz/8499</td>
      <td>Integer overflow</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH051</td>
      <td>Report <a href="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=8499">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/b245154fdebc9a78db163bc95959c6c8f5b4126f">link</a></td>
      <td>pdfimages or pdftoppm</td>
    </tr>
    <tr>
      <td>Bug #101366</td>
      <td>0-pointer dereference</td>
      <td>True</td>
      <td>poppler</td>
      <td>AAH052</td>
      <td>Report <a href="https://bugs.freedesktop.org/show_bug.cgi?id=101366">link</a></td>
      <td>Fix <a href="https://gitlab.freedesktop.org/poppler/poppler/commit/e1b5053e54b0ef7d6b09f3b9c97883db533d509a">link</a></td>
      <td>pdftoppm. Discovered by OSS-Fuzz</td>
    </tr>
  </tbody>
</table>