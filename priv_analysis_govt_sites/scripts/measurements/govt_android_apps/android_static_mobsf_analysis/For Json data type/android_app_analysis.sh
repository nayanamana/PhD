#!/bin/bash
apikey=$1
mkdir output
mkdir "output/permissions"
mkdir "output/trackers"
mkdir "output/db"
mkdir "output/json"
curl --url "http://localhost:8000/api/v1/scans" -H "Authorization:$apikey" | tr , '\n' | grep URL > "output/db/temp.txt"
IFS=$'\n' read -d '' -r -a data <"output/db/temp.txt"
k=0
while [ $k -ne ${#data[@]} ]
do
apkname=$(cat "output/db/temp.txt" | sed -n $(( 1+$k ))p | cut -f1 -d "&" | sed 's/.*=//')
apkhash=$(cat "output/db/temp.txt" | sed -n $(( 1+$k ))p | sed 's/^.*checksum/checksum/'| sed 's/.*=//' | cut -f1 -d "\"")
echo "$apkname:$apkhash" >> "output/db/result.txt"
(( k++ ))
done
j=0
IFS=$'\n' read -d '' -r -a line <"output/db/result.txt"
while [ $j -ne ${#line[@]} ]
do
hash=$(echo ${line[j]} | sed 's/.*://')
curl -X POST --url http://localhost:8000/api/v1/report_json --data "hash=$hash" -H "X-Mobsf-Api-Key:$apikey" > "output/json/$(echo ${line[j]} | cut -f1 -d ":").json"
(( j++ ))
done
l=0
while [ $l -ne ${#line[@]} ]
do
name=$(echo ${line[l]} | cut -f1 -d ":")
cat "output/json/$name.json" | sed 's/^.*target_sdk/target_sdk/'|tr , '\n' | awk '/certificate_analysis/{stop=1} stop==0{print}' | grep status | grep dangerous |  sed 's/.*permissions//' | sed -e '1s/^.//' | sed -e '1s/^.//' | sed -e '1s/^.//' | sed -e '1s/^.//' | cut -f1 -d ":" | sed 's/\"//' | sed 's/\"//' > "output/permissions/$name.txt"
cat "output/json/$name.json" | sed 's/^.*total_trackers/total_trackers/'|tr , '\n' | awk '/playstore_details/{stop=1} stop==0{print}' | tr [ "\n" | sed '1d'| sed '1d' | cut -f1 -d ":" | sed 's|[{"},]||g'  | cut -f1 -d "]" > "output/trackers/$name.txt"
(( l++ ))
done
