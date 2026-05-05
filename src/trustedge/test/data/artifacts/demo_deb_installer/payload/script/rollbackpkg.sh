#!/bin/bash
echo "Rollback removing package $1"
sudo dpkg -r $1
if [ $? -eq 0 ]
then
   echo "Rollback was successful"
   exit 0
else
   echo "Rollback failed"
   exit 1
fi
