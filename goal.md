# Crypto inventory tool

## End goal 
- crypto network map
- all ellyptic curves all rsa keys
- all post quantum
- map ip address -> cipher
- log files continuously but we want a database
- open port scanning (active)
- passive port scanning (sniffing)
- grabbing headers
- identifying cryptographis
- database for reporting
- GUI
- multithreading

## Work environment

- the main input is the ip range
- our tool is inspecting every ip:port pair in that range
- the output is a compiled view of assets that we've managed to acquire
- example: a view like this [banner, ip, port, cipher_suites] for ssl/tls
- similar for ssh and other protocols but there might be an unified view
- another view is a list of all keys

