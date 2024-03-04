#!/bin/sh
rm -rf ./build
# shellcheck disable=SC2164
mkdir build && cd build && cmake .. && make
echo "build done,coping plugin ..."
cp -r ./libplugin-quic.so /home/songyibao/Downloads/neuron-main/build/plugins/
echo "copy done, refresh http://127.0.0.1:7000"
#cp ./tmp/plugins.json ./build/persistence/
#echo "copy dashboard done"
#echo "starting neuron"
## sudo /home/songyibao/Downloads/neuron-main/build/neuron --log
## systemctl stop neuron
## systemctl start neuron
#echo "success,listening at: http://127.0.0.1:7000"
#cd build
## systemctl stop neuron
## systemctl start neuron
#./neuron --log
