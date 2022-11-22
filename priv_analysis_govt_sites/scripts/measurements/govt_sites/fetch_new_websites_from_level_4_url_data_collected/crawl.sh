#!/bin/bash
mkdir result

doit() {
  ip="$1"
curl -L --max-time 10 --connect-timeout 10 $ip | grep -o '<a .*href=.*>'  | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | grep -Eo "https?://\S+" | grep // | sed '/https\|http/!d' | sed 's/^http\(\|s\):\/\///g' | sed '/\.jpg/d;/\.mp4/d;/\.docx/d;/\.xls/d;/viber/d;/whatsapp/d;/youtube/d;/facebook/d;/instagram/d;/mailto/d;/phone/d;/twitter/d;/\.pdf/d' | sort | awk '!_[$0]++'
}
export -f doit

i=0
	while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls level4_urls)
j=0

while [ $j -ne ${#array[@]} ]
do	

echo "Working with ${array[j]}" | tee report.log
parallel -k -j 230  doit < "level4_urls/"${array[j]} >> "result/"${array[j]}

(( j++ ))
done


	
exit
 curl -L --max-time 10 --connect-timeout 10 $ip | grep -o '<a .*href=.*>'  | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | grep -Eo "https?://\S+" | grep // | sed '/https\|http/!d' | sed 's/^http\(\|s\):\/\///g' | sed '/\.jpg/d;/\.mp4/d;/\.docx/d;/\.xls/d;/viber/d;/whatsapp/d;/youtube/d;/facebook/d;/instagram/d;/mailto/d;/phone/d;/twitter/d;/\.pdf/d' | sed 's:/.*::' | sort | awk '!_[$0]++'
