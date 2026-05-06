#!/usr/bin/bash

while [[ "$#" -gt 0 ]]; do
        case "$1" in
         -v)
          verbose=true
          ;;
        esac
        shift
done

if [ "$verbose" = true ]; then
        echo "Verbose mode enabled" >&2
fi

cat <<EOF
{
     "location": "India",
     "cpu_id": "806ED",
     "operating_system": "Android"
}
EOF