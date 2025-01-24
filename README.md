# linux-lwip-mbedtls

### download

git clone https://github.com/diewelt/linux-lwip-mbedtls.git<br/>
cd linux-lwip-mbedtls<br/>
git submodule init<br/>
git submodule update<br/>

### build

cd linux-lwip-mbedtls<br/>
./xx<br/>

### additional info

가성머신 상에서 사용하도록 고안하였다. 소스를 내려받기 위해서는 네트워크 인터페이스를 활성화한다.

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500<br/>
        inet 192.168.1.115  netmask 255.255.255.0  broadcast 192.168.1.255<br/>
        inet6 fe80::a00:27ff:fe90:84d4  prefixlen 64  scopeid 0x20<link><br/>
        ether xx:xx:xx:xx:xx:xx  txqueuelen 1000  (Ethernet)<br/>
        RX packets 1340228  bytes 1073176941 (1.0 GB)<br/>
        RX errors 0  dropped 11138  overruns 0  frame 0<br/>
        TX packets 305804  bytes 23823829 (23.8 MB)<br/>
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0<br/>

실행 파일을 빌드한 이후에 테스트를 위해 다시 네트워크 인터페이스를 비활성화한다.

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500<br/>
        ether xx:xx:xx:xx:xx:xx  txqueuelen 1000  (Ethernet)<br/>
        RX packets 1340271  bytes 1073180200 (1.0 GB)<br/>
        RX errors 0  dropped 11139  overruns 0  frame 0<br/>
        TX packets 305812  bytes 23824660 (23.8 MB)<br/>
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0<br/>

이 상태에서 build/TestProject를 수퍼유저 권한으로 실행한다. 그리고 호스트 머신 상에서 테스트 프로그램을 실행한다.

test/netif.c 파일에서 수정이 필요할 수도 있는 내용은 다음과 같다.

* char *dev = "enp0s3";
* u8_t mac_addr[6] = { 0x08, 0x00, 0x27, 0x90, 0x84, 0xd4 };

test/lwip.h 파일에서 수정이 필요할 수도 있는 내용은 다음과 같다.

* #define TCP_REMOTE_SERVER_ADDR    ((22 << 24) | (1 << 16) | (168 << 8) | (192))

IPv4 주소는 DHCP를 통해서 내려받는다.

테스트 프로그램 안에서 세 종류의 네트워크 앱이 실행된다.

* cliet : 192.168.1.22:7777
* server : 0.0.0.0:7777
* https server : 0.0.0.0:443

가상의 ethernet interface 는 DHCP 를 통해서 ipv4 address 를 내려받는다. 또한 mDNS가 설정되어 있으므로 avahi-browse 를 이용해서 ipv4 address 를 알아낼 수 있다. 호스트 이름은 testlwip 이다.

* avahi-browse -a
* ping testlwip.local
