#!/bin/bash
echo "Rollback removing configuration file $1 from location $2"
rm $2/$1
if [ $? -eq 0 ]
then
   echo "Rollback was successful"
   exit 0
else
   echo "Rollback failed"
   exit 1
fi
