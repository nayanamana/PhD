#!/bin/bash
i=0
mkdir tmp1
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
curl -L -s ${url[k]} | grep "mailto\:" | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | sed '/\.jpg/d;/\.mp4/d;/\.docx/d;/android/d;/google/d;/whatsapp/d;/youtube/d;/facebook/d;/twitter/d;/\.pdf/d' | sed 's/^http\(\|s\):\/\///g' | sed 's:/.*::' | sed 's:<.*::' | sort | awk '!_[$0]++'
read -p "Do you wish store the URL" VAR
if [[ $VAR == *"y"* ]]; then
       echo ${url[k]} >> "tmp1/${array[j]}"
       clear
   fi
   clear
    (( k++ ))
done

(( j++ ))
done

exit
