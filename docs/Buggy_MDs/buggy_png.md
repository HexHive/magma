<table border="0" class="dataframe">
  <thead>
    <tr style="text-align: center;">
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
      <td>CVE-2019-6129</td>
      <td>Memory leak</td>
      <td><div align="center">&#10007;</div></td>
      <td>pngcp</td>
      <td></td>
      <td></td>
      <td></td>
      <td>pngcp fails to free allocated info struct upon error. Not a core bug.</td>
    </tr>
    <tr>
      <td>CVE-2019-7317</td>
      <td>Use-after-free</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH002</td>
      <td></td>
      <td></td>
      <td>Only triggered if the application uses the simplified API (png_image_begin_read...).</td>
    </tr>
    <tr>
      <td>CVE-2018-14048</td>
      <td>Use-after-free</td>
      <td><div align="center">&#10007;</div></td>
      <td>pnm2png</td>
      <td></td>
      <td></td>
      <td></td>
      <td>A specially-crafted input can crash a sample program in a place that's outside of the scope of libpng.</td>
    </tr>
    <tr>
      <td>CVE-2018-13785</td>
      <td>Integer overflow, divide by zero</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH001</td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2016-10087</td>
      <td>0-pointer dereference</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Context-dependent. To be vulnerable, an application has to load a text chunk into the png structure, then delete all text, then add another text chunk to the same png structure. Highly unlikely to be triggered by a crafted PNG file.</td>
    </tr>
    <tr>
      <td>CVE-2016-3751</td>
      <td>Unspecified</td>
      <td><div align="center">&#10007;</div></td>
      <td>android/libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>No released information.</td>
    </tr>
    <tr>
      <td>CVE-2015-8540</td>
      <td>Integer underflow, OOB read</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Vulnerability in pngwutil.c, which is not used when reading a file. Cannot be triggered by a crafted PNG file.</td>
    </tr>
    <tr>
      <td>CVE-2015-8472</td>
      <td>API inconsistency</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH003</td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2015-7981</td>
      <td>Integer underflow, OOB read</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Bug in png_convert_to_rfc1123() which is never called within libpng. Only applications that call this function are vulnerable.</td>
    </tr>
    <tr>
      <td>CVE-2015-0973</td>
      <td>Integer overflow</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH004</td>
      <td></td>
      <td></td>
      <td>PoC not available due to size constraints.</td>
    </tr>
    <tr>
      <td>CVE-2014-9495</td>
      <td>Integer overflow, Buffer overflow</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH005</td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2014-0333</td>
      <td>Infinite loop (DoS)</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Only applications using the progressive reader are affected.</td>
    </tr>
    <tr>
      <td>CVE-2013-7354</td>
      <td>Integer overflow, Buffer overflow</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>libpng calls vulnerable function internally only with num_unknowns==1. Cannot be triggered by a crafted PNG file.</td>
    </tr>
    <tr>
      <td>CVE-2013-6954</td>
      <td>0-pointer dereference</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH008</td>
      <td></td>
      <td></td>
      <td>Only triggered if application applies the EXPAND transformation (expands the palette over the samples).</td>
    </tr>
    <tr>
      <td>CVE-2012-3425</td>
      <td>Integer underflow, OOB read</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Vulnerable function was entirely removed since libpng-1.2.48.</td>
    </tr>
    <tr>
      <td>CVE-2011-3464</td>
      <td>Off-by-one buffer overflow</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>png_formatted_warning() function was drastically refactored to avoid the overflow. (git diff v1.5.7 v1.5.8beta01 -- pngerror.c).</td>
    </tr>
    <tr>
      <td>CVE-2011-3048</td>
      <td>0-pointer dereference</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH006</td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>(Unspecified)</td>
      <td>Memory leak</td>
      <td><div align="center">&#10003;</div></td>
      <td>libpng</td>
      <td>AAH007</td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>CVE-2019-17371</td>
      <td>Memory leak</td>
      <td><div align="center">&#10007;</div></td>
      <td>gif2png</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Not a core bug.</td>
    </tr>
    <tr>
      <td>CVE-2018-14550</td>
      <td>Stack buffer overflow</td>
      <td><div align="center">&#10007;</div></td>
      <td>pnm2png</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Not a core bug.</td>
    </tr>
    <tr>
      <td>CVE-2017-12652</td>
      <td>Improper input validation</td>
      <td><div align="center">&#10007;</div></td>
      <td>libpng</td>
      <td></td>
      <td></td>
      <td></td>
      <td>Way too many changes.</td>
    </tr>
  </tbody>
</table>