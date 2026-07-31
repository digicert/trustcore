TAP_SERVER_DIR=/home/admin/mocana/tap_server

export LD_LIBRARY_PATH=${TAP_SERVER_DIR}/moctpm2_tools/libs
cd ${TAP_SERVER_DIR}/moctpm2_tools/bin
./nanotap_server_bin --conf=taps.conf --modconfdir=./ > ${TAP_SERVER_DIR}/tap_server.log 2>&1 &
