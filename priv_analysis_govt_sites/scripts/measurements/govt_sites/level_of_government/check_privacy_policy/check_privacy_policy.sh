url=$1
length_of_url1=${#url}
length_of_url=$(( 140 + $length_of_url1)) 
length_of_header=$(( 144 + $length_of_url1)) 
#echo $length_of_header
sessionid=$(curl -i -s -k  -X $'GET' -H $'Host: pribot.org' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.7,fr-CA;q=0.3' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: https://pribot.org/bot?company=canada.ca' -H $'DNT: 1' -H $'Connection: close' -H $'Cookie: sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=m1Fo9ZSw6Ug2VulUAFEY' -b $'sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=m1Fo9ZSw6Ug2VulUAFEY' $'https://pribot.org/socket.io/?EIO=3&transport=polling&t=NTZCS24' | grep -a "Cookie" | cut -f1 -d ";" | rev | cut -f1 -d "=" | rev)
step2=$(echo "curl -i -s -k  -X $'POST' -H $'Host: pribot.org' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.7,fr-CA;q=0.3' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: https://pribot.org/bot?company=canada.ca' -H $'Content-type: text/plain;charset=UTF-8' -H $'Content-Length: $length_of_header' -H $'DNT: 1' -H $'Connection: close' -H $'Cookie: sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=9KbUcBfhLahnWaBWAFFf' -b $'sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=9KbUcBfhLahnWaBWAFFf' --data-binary $'$length_of_url:42[\"send\",{\"type\":\"greeting\",\"message\":\"fasttrack 6765654321\",\"auxiliaryMessage\":\"$url\",\"who\":\"55eeC6wYYBeeIKZ\",\"browserID\":\"61a3e70005c918c8\"}]' $'https://pribot.org/socket.io/?EIO=3&transport=polling&t=NTZCSMa&sid=$sessionid'")
eval $step2 > /dev/null 2>&1
step3=$(echo "curl -i -s -k  -X $'GET' -H $'Host: pribot.org' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.7,fr-CA;q=0.3' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: https://pribot.org/bot?company=canada.ca' -H $'DNT: 1' -H $'Connection: close' -H $'Cookie: sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=Cn_tQgFX3VzH8O1BAFFI' -b $'sessionId=s%3AyqW5P0sjkSvtk5_t-vfObEHzml6vEQaF.v7h7k%2F%2BJj4jwKIIfNMfQKmUV4JYRzmD1icNyOgSfj9E; _pk_id.1.910e=61a3e70005c918c8.1612276185.1.1612276941.1612276185.; _pk_ses.1.910e=1; randomId=61a3e70005c918c8; visitedBefore=true; io=Cn_tQgFX3VzH8O1BAFFI' $'https://pribot.org/socket.io/?EIO=3&transport=polling&t=NTZCSMb&sid=$sessionid'")
op=$(eval $step3 | grep -a "2:40")
if [[ "$op" == "2:40" ]]; then
    privacy="no"
else
    privacy="yes"
fi
python3 http_https_privacy_policy.py "$url" "$privacy"



