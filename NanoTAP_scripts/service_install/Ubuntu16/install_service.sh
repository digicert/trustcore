#! /bin/bash
echo "==========================================================================="
echo "This script will install Mocana NanoTAP service on Ubuntu 15.04 and later"
echo "==========================================================================="

unamestr=`uname -s`
os_version=`/usr/bin/lsb_release -rs 2>&1`

start_os_ver="15.04"
#target_os_ver="16.04"

function version() { echo "$@" | awk -F . '{ printf("%02d%02d\n", $1,$2); }'; }

if [ "$(version "$os_version")" -lt "$(version "$start_os_ver")" ]
then
  echo "This script is only for Ubuntu $start_os_ver and later!"
  exit 1
fi

if (( $(id -u) )) ; then
  echo "This script needs to run as root!"
  exit 1
fi

if [[ "$unamestr" == 'Linux' ]]; then
  chown $USER:$USER /usr/sbin/tcti_server

  cp ./NanoTAP_scripts/service_install/Ubuntu16/nanotap.service /lib/systemd/system/
  ln -sf /lib/systemd/system/nanotap.service /etc/systemd/system/nanotap.service
  systemctl daemon-reload
fi

echo ""
echo "Install successful"
