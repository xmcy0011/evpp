# Build

## Use Vcpkg

1. vcpkg
```bash
$ git clone https://github.com/Microsoft/vcpkg.git
$ cd vcpkg 
$ sudo ./bootstrap-vcpkg.sh
$ vim ~/.bashrc
# vcpkg
export PATH=/home/jack/data/vcpkg:$PATH
```

2. 使用vcpkg 安装依赖
```bash
$ vcpkg install libevent
$ vcpkg install glog
$ vcpkg install openssl
$ vcpkg install boost
```

3. build
```bash
$ -DCMAKE_TOOLCHAIN_FILE=/home/xuyc/data/vcpkg/scripts/buildsystems/vcpkg.cmake
```

## Centos 7

0. epel
```bash
$ yum install epel-release -y 
```

1. cmake
```bash
$ yum install cmake # 2.8 需要升级为3
$ wget https://cmake.org/files/v3.18/cmake-3.18.2.tar.gz
$ tar -zxvf cmake-3.18.2.tar.gz
$ cd cmake-3.18.2
$ ./bootstrap
$ gmake && sudo gmake install
$ /usr/local/bin/cmake --version
$ ln -s /usr/local/bin/cmake /usr/bin/ # 建立软连接
$ cmake --version
```

2. libevent
```bash
$ yum install libevent-devel
```

3. glog
```bash
# gflags
$ sudo yum install gflags-devel

# glog
$ git clone https://github.com/google/glog.git
$ cd glog
$ cmake -S . -B build -G "Unix Makefiles"
$ cmake --build build                        # build
$ sudo cmake --build build --target install  # install
```

4. openssl
```bash
$ yum install openssl-devel
```

5. boost
```bash
$ yum install boost-devel
```

6. git clone
```bash
$ git clone https://github.com/xmcy0011/evpp.git
$ cd evpp
$ git submodule update --init --recursive
```

## Ubuntu

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

4. openssl
```bash
$ sudo apt-get install openssl
```

5. git clone 
```bash
$ git clone https://github.com/xmcy0011/evpp.git
$ cd evpp
$ git submodule update --init --recursive
```

5. clion
    1. Clion打开evpp目录
    2. Build->Build Project

## SSL证书生成

生成自签名证书命令如下：
1. 生成私钥
```bash
$ openssl genrsa -out google.com.key 2048
```

2. 生成CSR（证书签名请求）
```bash
$ openssl req -new -out google.com.csr -key google.com.key

Country Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:Shanghai
Locality Name (eg, city) []:Shanghai
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Google Ltd
Organizational Unit Name (eg, section) []:google.com
Common Name (e.g. server FQDN or YOUR name) []:*.google.com #这一项必须和你的域名一致
Email Address []:kefu@google.com
A challenge password []:fG!#tRru
An optional company name []:Google.com
```
3. 生成自签名证书（100年过期）
```bash
$ openssl x509 -req -in google.com.csr -out google.com.cer -signkey google.com.key -CAcreateserial -days 36500
```

4. 生成服务器crt格式证书
```bash
$ openssl x509 -inform PEM -in google.com.cer -out google.com.crt
```

5. 生成PEM公钥
```bash
$ openssl x509 -in google.com.crt -outform PEM -out google.com.pem
```

最后，google.com.pem 和 google.com.key 是本程序需要的 公钥和私钥

附录：
- 生成IOS客户端p12格式根证书（输入密码fG!#tRru）
```bash
$ openssl pkcs12 -export -clcerts -in google.com.cer -inkey google.com.key -out google.com.p12
```
- 生成Android客户端bks格式证书
```bash
# $ 略
```