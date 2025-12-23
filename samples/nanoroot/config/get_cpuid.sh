#!/bin/bash

# sudo dmidecode -t processor | grep ID | awk '{print $2, $3, $4, $5, $6, $7, $8, $9}'
cpuid | grep "processor serial number" | awk 'NR==2{print $5}'
