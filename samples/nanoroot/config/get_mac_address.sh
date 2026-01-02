#!/bin/bash

ip link show $1 | grep -Po 'link/ether \K([0-9a-f]{2}:){5}[0-9a-f]{2}' 
