# Build

## Base

1. glog
```bash
$ sudo apt-get install libgoogle-glog-dev
```

2. libevent
```bash
$ sudo apt-get install libevent-dev
```

3. boost
```bash
$ sudo apt-get install libboost1.71-dev
# 缺什么搜索什么，apt search libboost-thread
$ sudo apt-get install libboost-system1.71-dev
$ sudo apt-get install libboost-thread1.71-dev
$ sudo apt-get install libboost-atomic1.71-dev
```

4. git clone 
```bash
$ git clone https://github.com/xmcy0011/evpp.git
$ cd evpp
$ git submodule update --init --recursive
```

## Ubuntu 20

1. Clion打开evpp目录
2. Build->Build Project
