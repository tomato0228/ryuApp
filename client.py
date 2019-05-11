from scapy.all import *
from scapy.layers.l2 import ARP

import validation

host_v = {'seed': '4gvHivysAcFKeBFR', 'len': 3328}

conf.vert = 1


def pack_callback(pcap):
    if pcap[ARP].op == 2:
        return
    src_ip = pcap[ARP].psrc
    src_mac = pcap[ARP].hwsrc
    dst_ip = pcap[ARP].pdst
    dst_mac = pcap[ARP].hwdst
    if dst_ip != '10.0.0.201' or dst_mac != '66:66:66:66:66:66':
        return

    isrc = "10.0.0.13"
    msrc = "00:00:00:00:00:03"

    try:
        data = pcap[Raw].load

        print('------%s', data)

        if type == 8:
            if validation.aesencrypt(validation.hash_key(host_v['seed'], host_v["len"]), host_v["seed"]) == data:
                data_t = validation.aesencrypt(validation.hash_key(host_v['seed'], host_v["len"] - 1), host_v["seed"])
                # 加密完成后将哈希次数减 2
                host_v["len"] = host_v["len"] - 2
                send(ARP(op=2, psrc=isrc, hwsrc=msrc, pdst=src_ip, hwdst=src_mac) / Raw(data_t))
            else:
                send(ARP(op=2, psrc=isrc, hwsrc=msrc, pdst=src_ip, hwdst=src_mac) / Raw(b'test data'))
    except BaseException:
        print('------------------------')
        send(ARP(op=2, psrc=isrc, hwsrc=msrc, pdst=src_ip, hwdst=src_mac) / Raw(b'test data'))


pcap = sniff(iface="h1-eth0", filter="arp", count=0, prn=pack_callback)
