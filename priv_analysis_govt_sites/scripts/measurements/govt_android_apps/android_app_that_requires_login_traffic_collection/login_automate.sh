#!/bin/bash
i=0
dir=$1
mkdir login_traffic1
IFS=$'\n' read -d '' -r -a array < login_app.txt
j=0
while [ $j -ne "${#array[@]}" ]
do
adb install "$dir/${array[j]}"
wait
x-terminal-emulator -e "mitmproxy -p 1337 -s mitmpcap.py"
wait
adb shell monkey -p $(echo ${array[j]} | rev | cut -c 5- | rev) --pct-touch 100 --pct-syskeys 0 -v 1
exec < /dev/tty
echo -n "Do you wish to continue"
read CONT
adb shell ps | awk '/com\.android\.commands\.monkey/ { system("adb shell kill " $2) }'
wait
killall mitmproxy
mv output.pcap "login_traffic/$(echo ${array[j]} | rev | cut -c 5- | rev).pcap"
wait
adb uninstall $(echo ${array[j]} | rev | cut -c 5- | rev)
sleep 5
(( j++ ))
done
