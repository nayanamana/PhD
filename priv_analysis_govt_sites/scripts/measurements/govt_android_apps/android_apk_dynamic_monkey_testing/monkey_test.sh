#!/bin/bash
i=0
dir=$1
mkdir traffic
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "$dir")
j=0

while [ $j -ne ${#array[@]} ]
do
l=0
while read line
	do
    		apk_array[ $l ]="$line"        
    		(( l++ ))
	done < <(ls "$dir/${array[j]}")
k=0
while [ $k -ne ${#apk_array[@]} ]
do
mkdir "traffic/${array[j]}"
adb install "$dir/${array[j]}/${apk_array[k]}"
wait
adb shell dumpsys package | grep -Eo "^[[:space:]]+[0-9a-f]+[[:space:]]+$(echo ${apk_array[k]} | rev | cut -c 5- | rev)/[^[:space:]]+" | grep -oE "[^[:space:]]+$" > temp.txt
x-terminal-emulator -e "mitmproxy -p 1337 -s mitmpcap.py"
sleep 20
IFS=$'\n' read -d '' -r -a activity < temp.txt
m=0
while [ $m -ne ${#activity[@]} ]
do
adb shell am start -n ${activity[m]}
wait
(( m++ ))
done
wait
adb shell monkey -p $(echo ${apk_array[k]} | rev | cut -c 5- | rev) --pct-touch 100 --pct-syskeys 0 -v 5000
wait
adb shell ps | awk '/com\.android\.commands\.monkey/ { system("adb shell kill " $2) }'
wait
killall mitmproxy
mv output.pcap "traffic/${array[j]}/$(echo ${apk_array[k]} | rev | cut -c 5- | rev).pcap"
wait
adb uninstall $(echo ${apk_array[k]} | rev | cut -c 5- | rev)
sleep 5
wait
(( k++ ))
done
(( j++ ))
done
