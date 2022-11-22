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
python3 ~/Desktop/Mobile-Security-Framework-MobSF/scripts/mass_static_analysis.py -d "$dir/${array[j]}" -s 0.0.0.0:8000 -k 0f8798480eb95bdb1facbddb3b08251a475ad08a4c69cb5cfaa9d0734a21a30d 
wait 
(( j++ ))
done

exit

