#NetFlow Data Generator
This project aims to generate NetFlow data from tcpdump file.

###### The sample data comes from MAWILab.

##Setup

###Install softflowd
```bash
wget https://code.google.com/p/softflowd/downloads/detail?name=softflowd-0.9.9.tar.gz&can=2&q=
./configure
make
sudo make install
```

##Quick start

###Dump
```bash
$ python nfDump.py
$ softflowd -D -r data/1MB.dump -v 5 -n 127.0.0.1:41300
```

###Parse
```bash
$ python nfParser.py
$ softflowd -D -r data/1MB.dump -v 5 -n 127.0.0.1:41300
```
