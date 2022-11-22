param(
    [string]$hostspotpath
 )
 
cd $hostspotpath 
tshark -Y "http.request" -T fields -e frame.number -e ip.src  -e tcp.srcport  -e ip.dst  -e tcp.dstport -e  http.request.version -e http.user_agent  -e http.request.method -e http.host -e http.request.full_uri  -e http.referer -e  http.cookie -e http.request.line  -e  frame.time -e  frame.time_epoch  -e  text -e http.file_data  -e eth.src -r traffic.pcap -E header=y -E separator=/t -E  quote=d -E occurrence=a  -E aggregator=”~”| %{$_ -replace "`r",""}  | %{$_ -replace "`n",""}  | %{$_ -replace "^p",""}| sed 's/\r|\n//'> httprequest.txt
$original_file =(Get-Item -Path ".\").FullName + '/httprequest.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n~", "~"
[IO.File]::WriteAllText($original_file, $text)
$original_file =(Get-Item -Path ".\").FullName + '/httprequest.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n ", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`r", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n`n", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n`n", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n<", "<"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`r`n", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`r", '}'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`n", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n}", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r}", '}'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n}", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace '`r`n"', '"'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace '`r"', '"'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace '`n"', '"'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`r`n", ">"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`r", ">"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`n", ">"
[IO.File]::WriteAllText($original_file, $text)
import-csv httprequest.txt -delimiter "`t" | export-csv httprequest.csv  -NoType
tshark -Y "http.response" -T fields -e  frame.number  -e http.request_in  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport  -e http.response.code -e http.response.code.desc -e http.response.phrase -e http.content_type -e http.content_length -e http.location -e http.set_cookie -e http.response.line -e  frame.time -e frame.time_epoch   -e  text   -e http.file_data  -r traffic.pcap -E header=y -E separator=/t -E  quote=d -E occurrence=a  -E aggregator=”~”  |  %{$_ -replace "`r",""}  | %{$_ -replace "`n",""}  | %{$_ -replace "^p",""}| sed 's/\r|\n//'>  httpresponse.txt
$original_file =(Get-Item -Path ".\").FullName + '/httpresponse.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n~", "~"
[IO.File]::WriteAllText($original_file, $text)
$original_file =(Get-Item -Path ".\").FullName + '/httpresponse.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n ", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`r", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n`n", ""
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n<", "<"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`r`n", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`r", '}'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "}`n", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n}", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r}", '}'
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n}", "}"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`r`n", ">"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`r", ">"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ">`n", ">"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ";`r`n", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ";`r", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ";`n", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "{`r`n", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "{`r", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "{`n", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "; `r`n", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "; `r", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "; `n", ";"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `r`n", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `r", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `n", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "/`r`n", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "/`r", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "/`n", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ",`r`n", ","
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ",`r", ","
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ",`n", ","
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `r`n", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `r", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace " `n", " "
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`t`r`n", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`t`r", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`t`n", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ":`r`n", ":"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ":`r", ":"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace ":`n", ":"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "=`r`n", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "=`r", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "=`n", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "&`r`n", "&"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "&`r", "&"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "&`n", "&"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nif", "if"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rif", "if"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nif", "if"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n$", "$"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r$", "$"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n$", "$"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nk", "k"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rk", "k"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nk", "k"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n!", "!"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r!", "!"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n!", "!"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n=", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r=", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n=", "="
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "-`r`n", "-"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "-`r", "-"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "-`n", "-"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nf", "f"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rf", "f"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nf", "f"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`ng", "g"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rg", "g"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`ng", "g"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n/", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r/", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n/", "/"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`ne", "e"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`re", "e"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`ne", "e"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nP", "P"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rP", "P"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nP", "P"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nc", "c"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n~", "~"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r~", "~"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n~", "~"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nv", "v"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rv", "v"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nv", "v"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n{", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r{", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`n{", "{"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`na", "a"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`ra", "a"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`na", "a"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`r`nb", "b"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`rb", "b"
[IO.File]::WriteAllText($original_file, $text)
$text = [IO.File]::ReadAllText($original_file) -replace "`nb", "b"
[IO.File]::WriteAllText($original_file, $text)
import-csv httpresponse.txt -delimiter "`t" | export-csv httpresponse.csv  -NoType
tshark -Y "websocket.payload" -T fields -e frame.number -e ip.src  -e tcp.srcport  -e ip.dst  -e tcp.dstport -e  http.request.version -e frame.protocols  -e http.request.method -e ip.host -e http.request.full_uri  -e http.referer -e  http.cookie -e http.request.line  -e  frame.time -e  frame.time_epoch  -e eth.src -e  text  -e http.file_data -r traffic.pcap -E header=y -E separator=/t -E  quote=n -E occurrence=a  -E aggregator=”~” | %{$_ -replace '"',''} | %{$_ -replace "'",""}  > websocket.txt
$original_file =(Get-Item -Path ".\").FullName + '/websocket.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n~", "~"
[IO.File]::WriteAllText($original_file, $text)
$original_file =(Get-Item -Path ".\").FullName + '/websocket.txt'
$text = [IO.File]::ReadAllText($original_file) -replace "`r`n`r`n`t", "`t"
[IO.File]::WriteAllText($original_file, $text)
import-csv websocket.txt -delimiter "`t" | export-csv websocket.csv  -NoType
