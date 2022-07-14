# How to start/use this example

1. It uses a tuntap device. On linux you can easily set this up running:
```commandline
 $ sudo ./make_tap0.sh <your-user-name>
```
2. Go to a terminal, go to smoltcp/k-v-Ohua and do:
```commandline
 $ <dir>/smoltcp/k-v-Ohua $ cargo run
```
3. Open another terminal window. Usinng ``socat`` you can issue the following commands to the store:
```commandline
 $ socat stdio tcp4-connect:192.168.69.1:6969 <<< "{\"Insert\":{\"key\":\"somekey\", \"value\":\"somevalue\"}}"

 $ socat stdio tcp4-connect:192.168.69.1:6969 <<< "{\"Read\":{\"key\":\"somekey\"}}"

 $ socat stdio tcp4-connect:192.168.69.1:6969 <<< "{\"Delete\":{\"key\":\"somekey\"}}"

 $ socat stdio tcp4-connect:192.168.69.1:6969 <<< "{\"Update\":{\"key\":\"somekey\", \"value\":\"somevalue\"}}"
```
Note: It's neccessary to escape ' " ' inside the messages, otherwise the program receives just a single string from the cli and will not be able to parse it as JSON.