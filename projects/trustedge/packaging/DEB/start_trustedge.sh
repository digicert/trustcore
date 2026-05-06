#!/bin/bash

if ! pgrep "trustedge" > /dev/null
then
    trustedge --daemon &
fi
