define($MAC 00:00:00:00:01:00);
source :: FromDevice;
dest :: ToDevice;


AddressInfo(
        IP1 192.168.56.105,//Public IP1
        IP2 192.168.56.106,//Public Ip2
        IP3 192.168.56.107,//Public IP3
        IP4 192.168.56.108,//PVT Ip4 for IP1
        IP5 192.168.56.109,//PVT IP5 for IP2
        IP6 192.168.56.110);//PVT Ip6 for IP3

c :: Classifier(
        12/0806 20/0001 38/c0a83869,//ARP Req for IP1
        12/0806 20/0001 38/c0a8386a,//ARP Req for IP2
        12/0806 20/0001 38/c0a8386b,//ARP REq for IP3
        12/0800 34/08,//ICMP
        -);

f :: IPFilter(
        0 dst host IP1,//ICMP IP1
        1 dst host IP2,//ICMP IP2
        2 dst host IP3,//ICMP IP3
        3 all);//Firewall for all others
/*
        A compound element which Pretty prints ICMP packet before NAT functionality
        Changes the ICMP dest address according to the outer-inner IP mapping
        Pretty Prints the ICMP packet which has an updated destination address
        Generates the Ping Response
        Changes the ICMP source address back according to the Inner-Outer IP mapping
        Sends the response back to complete the ping

*/
elementclass ICMPTranslator{
        $IPSRC, $IPDST |
        input->IPPrint(TIMESTAMP false)
        ->icmp :: ICMPPingRewriter(pattern $IPSRC $IPDST 0-65535 0 1,drop)
        ->IPPrint(TIMESTAMP false)
        ->CheckICMPHeader()
        ->ICMPPingResponder()
        ->IPPrint(TIMESTAMP false)
        ->[1]icmp[1]->EtherMirror()
        ->IPPrint(TIMESTAMP false)
        ->output
}

source->c;
//Generate the ARP Response to the corresponding Destination
c[0]->ARPPrint->Print('ARP for 192.168.56.105')->ARPResponder(IP1 $MAC)->dest;
c[1]->ARPPrint->Print('ARP for 192.168.56.106')->ARPResponder(IP2 $MAC)->dest;
c[2]->ARPPrint->Print('ARP for 192.168.56.107')->ARPResponder(IP3 $MAC)->dest;

//Handle ICMP packets
c[3]->Print('ICMP')->CheckIPHeader(14)->f;
c[4]->Discard;

f[0]->ICMPTranslator(IP1, IP4)->dest;
f[1]->ICMPTranslator(IP2, IP5)->dest;
f[2]->ICMPTranslator(IP3, IP6)->dest;
f[3]->Discard;

