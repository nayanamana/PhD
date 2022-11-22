#!/bin/bash
i=0
mkdir tmp3
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "android/")
j=0

while [ $j -ne ${#array[@]} ]
do
IFS=$'\n' read -d '' -r -a url <"android/${array[j]}"
k=0
while [ $k -ne ${#url[@]} ]
do
echo "************ Working With ${array[j]} ***************** "
echo ${url[k]}
curl -L -s ${url[k]} | grep "mailto\:" | grep "mailto\:" | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | sed '/\.jpg/d;/\.mp4/d;/\.docx/d;/android/d;/google/d;/whatsapp/d;/youtube/d;/facebook/d;/twitter/d;/mailto/d' | sed 's/^http\(\|s\):\/\///g' | sed 's:/.*::' | sed 's:<.*::' | sort | awk '!_[$0]++' > "store.txt"
var=$(cat store.txt | tail -n 1 | sed -e 's/^/http:\/\//' | awk -F/ '{sub(/^www\.?/,"",$3); print $3}')

if grep -Fxq "$var" "/root/Desktop/project_v4/v4.1/government_websites/${array[j]}"
then
echo ${url[k]} >> "tmp3/${array[j]}"
fi






    (( k++ ))
done

(( j++ ))
done

exit


if [[ -s test.txt ]]; 
then 
echo ${url[k]} >> "tmp2/${array[j]}"
fi



echo "parallel -j 200 curl -L --max-time 10 --connect-timeout 10 "${CURL_ARGS[@]}" -o '{#}'.curl_output '{}' :::: afganistan.txt"
