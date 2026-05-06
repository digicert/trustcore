#!/bin/bash
echo "Installing package $1"
sudo dpkg -i $1
if [ $? -eq 0 ]
then
   echo "Install was successful"
   exit 0
else
   echo "Install failed"
   exit 1
fi
