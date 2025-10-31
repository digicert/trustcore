# MQTT Build and Test Instructions

1. Extract cmocka

        cd mocn-mss
        file ./cmocka-1.1.5.tar.xz
        ls -l ./cmocka-1.1.5.tar.xz
        tar -xvf ./cmocka-1.1.5.tar.xz

2. Build MQTT client static lib

        export CMAKE_DIR=/opt/cmake
        export PATH=$CMAKE_DIR/bin:$PATH
        cd scripts/nanomqtt/mqtt_client/
        CM_ENV_STRIP_FUNC=1 ./build_mqtt_client.sh --libtype "static" --async --persist 
        cd ../../..
        ls -l ./bin_static

3. Build cmocka Library and mock Library

        cd cmocka-1.1.5
        mkdir build
        cd build
        cmake --version
        cmake -D WITH_STATIC_LIB=ON ..
        make
        cp ./src/libcmocka-static.a ../../bin_static
        cd ../..
        cp -r ./cmocka-1.1.5 ./thirdparty
        cd ./projects/mock
        ./build.sh --gdb

4. Build and run MQTT unit tests

        cd ../../projects/mqtt_testunit
        ./build.sh --gdb
        ./run.sh
        cd ../../

5. Build MQTT client static lib with streaming

        export CMAKE_DIR=/opt/cmake
        export PATH=$CMAKE_DIR/bin:$PATH
        cd scripts/nanomqtt/mqtt_client/
        CM_ENV_STRIP_FUNC=1 ./build_mqtt_client.sh --libtype "static" --streaming
        cd ../../..
        ls -l ./bin_static

6. Build and run unit tests with streaming 

        cd cmocka-1.1.5
        mkdir build
        cd build
        cmake --version
        cmake -D WITH_STATIC_LIB=ON ..
        make
        cp ./src/libcmocka-static.a ../../bin_static
        cd ../..
        cp -r ./cmocka-1.1.5 ./thirdparty
        echo "Building mock library"
        cd ./projects/mock
        ./build.sh --gdb
        echo "Building mqtt unit test"
        cd ../../projects/mqtt_testunit
        ./build.sh --gdb --streaming
        ./run.sh --streaming

# MQTT Build and Test Instructions for TrustCore Repo

1. Extract cmocka

        cd trustcore
        file ./cmocka-1.1.5.tar.xz
        ls -l ./cmocka-1.1.5.tar.xz
        tar -xvf ./cmocka-1.1.5.tar.xz

2. Build cmocka Library

        cd cmocka-1.1.5
        mkdir build
        cd build
        cmake --version
        cmake ..
        make
        cp ./src/libcmocka.* ../../lib
        cd ../..

3. Build MQTT client

        cmake -DDISABLE_SSH_SERVER=ON -DDISABLE_SSH_CLIENT=ON -DENABLE_MQTT_UNITTEST=ON -DENABLE_MQTT_ASYNC=ON -DENABLE_MQTT_PERSIST=ON -B build -S .
        cmake --build build 

4. Run MQTT unit tests

        ./projects/mqtt_testunit/run.sh

5. Build and run MQTT streaming tests

## Build with streaming enabled

    cmake -DDISABLE_SSH_SERVER=ON -DDISABLE_SSH_CLIENT=ON -DENABLE_MQTT_UNITTEST=ON -DENABLE_MQTT_STREAMING=ON -B build -S .
    cmake --build build 

## Run streaming tests only

    ./projects/mqtt_testunit/run.sh --streaming

