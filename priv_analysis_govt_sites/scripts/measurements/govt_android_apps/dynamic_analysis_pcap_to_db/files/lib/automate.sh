#!/bin/bash
i=0
dir=$1
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "$dir")
j=0

while [ $j -ne ${#array[@]} ]
do 
echo "Working with ${array[j]}"
k=$(( $j + 1 ))
sqlite3 /root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/crawl-data.sqlite "UPDATE "main"."crawl" SET "upload_crawl_id"=$k WHERE "_rowid_"='1';" ".exit"
wait
cp "$dir/${array[j]}" "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/"
wait
mv "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/${array[j]}" "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/traffic.pcap"
wait
cat "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/temp_params.json"  | jq '.hotspotName = $v' --arg v ${array[j]} | jq '.package_name = $v' --arg v ${array[j]} | jq '.ISP = $v' --arg v ${array[j]} > "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/test.json"
wait
mv "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/test.json" "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/temp_params.json"
wait
python3 pcaptosql.py
wait
rm /root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/*.csv
wait
rm /root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/datasets/android_traffic/*.txt
wait
(( j++ ))
done
