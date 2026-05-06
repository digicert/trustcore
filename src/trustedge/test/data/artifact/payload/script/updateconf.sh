#!/bin/bash
echo "Copying configuration file $1 to location $2"
cp $1  $2
if [ $? -eq 0 ]
then
   echo "Copy was successful"
   exit 0
else
   echo "Copy failed"
   exit 1
fi
