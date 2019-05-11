from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, icmp, ipv4, arp, dhcp, ether_types
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3

import validation

# data structures to store Ip and MAC address of host
# and count of ARP packets per port
host = {}
PortCount = {}

# 主机逻辑信息表
host_v = validation.read_host_v("host_v.txt")

# 主机物理信息表
host_c = {}

# 缓存 ARP 请求包
send_arp_table = {}

# 缓存 MAC-IP对应表
arp_table = {}


class SimpleSwitch13(app_manager.RyuApp):
    # specify the openflow protocol to be used for the application here it is Open flow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # override the superclass init method and initialize mac_to_port table
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_addr = '66:66:66:66:66:66'
        self.ip_addr = '10.0.0.201'
        self.dhcp_ip = "10.0.0.101"
        self.dhcp_mac = "00:00:00:00:00:00"
        self.logger.info("主机逻辑信息表：")
        for key in host_v.keys():
            self.logger.info("\t%s: %s", key, host_v[key])
        # self.logger.info("%s", host_v)

    # This Function is called whenever EventOFPSwitchFeatures is triggered, that is when a new switch connects to the
    # controller It installs the table-miss flow entry as well as ARP packet entry so that the packets are sent to
    # the controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        # parsing of the packet
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install ARP -packet match entry
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        self.add_flow(datapath, 2, match, actions)

    # add_flow 是一个帮助函数，用于减少控制器应用程序中的代码
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # prepare a list of instructions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Constructing the flow mod
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)

        # Sending the flow mod
        datapath.send_msg(mod)

    # handle_spoof 方法用于对包应用操作并与 in_port 匹配，以便在特定时间内在该端口上阻止攻击者
    def handle_spoof(self, mac, msg):
        actions = []
        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        match = parser.OFPMatch(in_port=in_port)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                idle_timeout=60,
                                hard_timeout=60,
                                priority=20,
                                instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("\033[1;31m" + "安装了一个表项来从端口: %s 丢弃所有数据包" + "\033[0m", in_port)

    # _arp_handler 方法用于解码数据包并提取源和目标 IP 及 MAC 地址的 ARP 头
    # 此方法在发生洪泛攻击时检查端口计数，以便检查 ARP 包计数的阈值和
    # 如果计数超过阈值，则调用 handle_spoof 方法，该方法将在特定时间内阻塞攻击者。
    def _arp_handler(self, pkt_arp, msg):
        # 解码数据包以获得 MAC 和 IP 地址
        # 源主机
        arp_src_ip = pkt_arp.src_ip
        arp_src_mac = pkt_arp.src_mac
        # 目的主机
        arp_dst_ip = pkt_arp.dst_ip
        arp_dst_mac = pkt_arp.dst_mac
        # 接入位置
        # 交换机 ID
        dpid = msg.datapath.id
        # 交换机的端口号
        port = msg.match['in_port']

        # 如果是 ARP 响应，并且，目的主机是自己
        if str(pkt_arp.opcode) == str(arp.ARP_REPLY):
            # 打印 ARP 包内容
            self.logger.info("\033[1;34m" + "捕获到 ARP 响应数据包:\t 源 IP:%s\tMAC:%s\t目的 IP:%s\tMAC:%s\tSID:%s\tPORT:%s"
                             + "\033[0m", arp_src_ip, arp_src_mac, arp_dst_ip, arp_dst_mac, dpid, port)
            if arp_src_mac in send_arp_table and arp_dst_mac == self.mac_addr and arp_dst_ip == self.ip_addr:
                # TODO
                pkt = packet.Packet(msg.data)
                data = pkt.data
                # self.logger.info("\033[1;31m" + "data:%s" + "\033[0m", data)
                try:
                    # 解密的验证数据
                    data = validation.aesdecrypt(data, host_v[arp_src_mac]["seed"])
                    if data == validation.hash_key(host_v[arp_src_mac]["seed"], host_v[arp_src_mac]["len"]):
                        # 解密完成后将哈希次数减 1
                        host_v[arp_src_mac]["len"] = host_v[arp_src_mac]["len"] - 1
                        if host_c[str(arp_src_mac)][str("port")] == port:
                            # 攻击
                            self.handle_spoof(arp_src_mac, send_arp_table[arp_src_mac])
                        else:
                            # 更新主机物理信息表
                            host_c[arp_src_mac][str("sid")] = dpid
                            host_c[arp_src_mac][str("port")] = port
                    else:
                        # 攻击
                        self.handle_spoof(arp_src_mac, msg)
                        return
                except BaseException:
                    self.logger.info("\033[1;31m" + "验证失败" + "\033[0m")
                    # 攻击
                    self.handle_spoof(arp_src_mac, msg)
                send_arp_table.pop(arp_src_mac)
            return

        # 打印 ARP 包内容
        self.logger.info("\033[1;34m" + "捕获到 ARP 请求数据包:\t 源 IP:%s\tMAC:%s\t目的 IP:%s\tMAC:%s\tSID:%s\tPORT:%s"
                         + "\033[0m", arp_src_ip, arp_src_mac, arp_dst_ip, arp_dst_mac, dpid, port)

        if str(self.dhcp_ip) == str(arp_src_ip):
            self.dhcp_mac = arp_src_mac
            for key in host_c.keys():
                if str('ip') in host_c[key] and host_c[key][str('ip')] == str(arp_dst_ip):
                    # 发送 ARP 回应数据包
                    self._send_arp_reply_handler(msg, arp_dst_ip, key, self.dhcp_ip, self.dhcp_mac)
                    return

        if str(self.dhcp_ip) == str(arp_dst_ip):
            # 发送 ARP 回应数据包
            self._send_arp_reply_handler(msg, self.dhcp_ip, self.dhcp_mac, arp_src_ip, arp_src_mac)
            return

        # 已发送 ARP 请求，等待回应，对该主机的 ARP 请求数据包做丢弃处理
        if arp_src_mac in send_arp_table and host_c[str(arp_src_mac)][str("port")] != port:
            self.logger.info("已为该主机发送验证信息，丢弃该 ARP 请求数据包！")
            return

        # 检查每个端口的 ARP 包的数量
        # if port not in PortCount:
        #     PortCount.update({port: 1})
        # else:
        #     if PortCount[port] > 40:
        #         self.logger.info("\033[1;31m" + "\n 检测到 ARP 洪泛攻击 !!!" + "\033[0m")
        #         # 在特定时间内阻塞攻击者
        #         self.handle_spoof(arp_src_mac, msg)
        #         return
        #     elif str(pkt_arp.opcode) == str(arp.ARP_REQUEST):
        #         PortCount[port] += 1

        # 源主机的 MAC-IP 映射是否真实, MAC 不在主机物理信息表中直接丢弃
        if arp_src_mac in host_c.keys():
            if str(host_c[arp_src_mac]['ip']) != str(arp_src_ip):  # 源主机的 MAC-IP 映射是否和主机物理信息表中一样
                self.logger.info("\033[1;31m" + "\n****** ARP 欺骗检测: MAC 和 IP 映射不匹配 *****" + "\033[0m")
                self.handle_spoof(arp_src_mac, msg)
                # 盗用 IP 或者 MAC 的攻击方式
                return

        self.logger.info("\033[1;34m" + "源主机的 MAC-IP 映射真实" + "\033[0m")

        # MAC 地址是否真实
        if arp_src_mac in host_c.keys():  # 源主机 MAC 是否在配置验证信息表中
            if str(host_c[arp_src_mac]['sid']) != str(dpid) or str(host_c[arp_src_mac]['port']) != str(port):
                # MAC 对应的接入位置和配置验证信息表中接入位置不一样，进一步验
                # 向主机发送待验证的 ICMP 请求包
                self.logger.info("源主机的 MAC 地址真实性待进步一验证，发送验证信息！")
                self._send_arp_handler(msg, self.ip_addr, self.mac_addr, arp_src_ip, arp_src_mac)
                send_arp_table.update({arp_src_mac: msg})
                return

        self.logger.info("\033[1;34m" + "源主机的 MAC 地址真实" + "\033[0m")

        for key in host_c.keys():
            if str('ip') in host_c[key] and host_c[key][str('ip')] == str(arp_dst_ip):
                # 发送 ARP 回应数据包
                self._send_arp_reply_handler(msg, arp_dst_ip, key, arp_src_ip, arp_src_mac)
                return
        return

    # _dhcp_handler方法从接收的包中提取DHCP头来填充主机表。主机表用于存储IP地址与MAC地址的关联列表，并作为真实表进行进一步分析
    def _dhcp_handler(self, pkt_dhcp, msg):
        if pkt_dhcp.op == dhcp.DHCP_DISCOVER:
            # 打印收到的 DHCP_DISCOVER 数据包
            self.logger.info("\033[1;34m" + "收到 DHCP 数据包: IP : %s MAC : %s Op: %s" + "\033[0m",
                             pkt_dhcp.yiaddr, pkt_dhcp.chaddr, pkt_dhcp.op)
            # 交换机 ID
            dpid = msg.datapath.id
            # 交换机的端口号
            port = msg.match['in_port']
            # 更新主机物理信息表
            host_c.setdefault(str(pkt_dhcp.chaddr), {})
            host_c[str(pkt_dhcp.chaddr)][str("sid")] = str(dpid)
            host_c[str(pkt_dhcp.chaddr)][str("port")] = str(port)
            # 打印主机物理信息表
            self.logger.info("%s", host_c)

        # 解码数据包，得到ip地址和mac地址;检查 op = 2
        if pkt_dhcp.op == dhcp.DHCP_OFFER:
            # 打印收到的 DHCP_OFFER 数据包
            self.logger.info("\033[1;34m" + "收到 DHCP 数据包: IP : %s MAC : %s Op: %s" + "\033[0m",
                             pkt_dhcp.yiaddr, pkt_dhcp.chaddr, pkt_dhcp.op)
            # 保存 DHCP MAC
            if str(self.dhcp_mac) == str("00:00:00:00:00:00"):
                pkt = packet.Packet(msg.data)
                eth = pkt.get_protocols(ethernet.ethernet)[0]
                src = eth.src
                self.dhcp_mac = src
            # 交换机 ID
            dpid = msg.datapath.id
            # 交换机的端口号
            port = msg.match['in_port']
            # 更新主机物理信息表
            host_c[str(pkt_dhcp.chaddr)][str("ip")] = str(pkt_dhcp.yiaddr)
            # 打印主机物理信息表
            # self.logger.info("%s", host_c)
            self.logger.info("主机物理信息表：")
            for key in host_c.keys():
                self.logger.info("\t%s: %s", key, host_c[key])
        return

    # 发送 ARP 回应数据包
    def _send_arp_reply_handler(self, msg, src_ip, src_mac, dst_ip, dst_mac):
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 封装 ARP 回应数据包
        ARP_Reply = packet.Packet()
        ARP_Reply.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=dst_mac,
            src=src_mac))
        ARP_Reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip))
        ARP_Reply.data = None
        self.logger.info("发送 ARP 响应数据包: 源 IP:%s\tMAC:%s\t 目的 IP:%s\tMAC:%s 端口:%s",
                         src_ip, src_mac, dst_ip, dst_mac, port)
        self._send_packet(datapath, port, ARP_Reply)

    # 发送 ARP 请求数据包
    def _send_arp_handler(self, msg, src_ip, src_mac, dst_ip, dst_mac):
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 封装 ARP 请求数据包
        ARP_Request = packet.Packet()
        ARP_Request.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=dst_mac,
            src=src_mac))
        ARP_Request.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip, ))
        # 加密的验证数据
        data = validation.aesencrypt(
            validation.hash_key(host_v[str(dst_mac)]["seed"], host_v[str(dst_mac)]["len"]),
            host_v[str(dst_mac)]["seed"])
        # 加密完成后将哈希次数减 1
        host_v[str(dst_mac)]["len"] = host_v[str(dst_mac)]["len"] - 1
        ARP_Request.add_protocol(data)
        self.logger.info("发送 ARP 请求数据包: 源 IP:%s\tMAC:%s\t 目的 IP:%s\tMAC:%s",
                         self.ip_addr, self.mac_addr, dst_ip, dst_mac)
        self._send_packet(datapath, port, ARP_Request)

    # 通过 PacketOut 发送数据包
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("发送 ARP 数据包")
        self.logger.info("--------------------")
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        # 封装 PacketOut 包
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        # 发送 PacketOut 包
        datapath.send_msg(out)

    # 这是控制器应用程序的主要逻辑，当交换机将数据包设置到控制器时调用该逻辑
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        # self.logger.info("packet info - %s" , pkt)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # 忽略 LLDP 包
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # 检查ARP包和DHCP包
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)

        # ARP 包, 调用 arp_handler
        if pkt_arp:
            self._arp_handler(pkt_arp, msg)
            return

        # DHCP 包, 调用 dhcp_handler
        if pkt_dhcp:
            self._dhcp_handler(pkt_dhcp, msg)

        self.mac_to_port.setdefault(dpid, {})

        # 学习一个mac地址，以避免下次洪范。
        self.mac_to_port[dpid][src] = in_port

        # 目标 MAC 是否在 MAC-IP 映射表中
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
