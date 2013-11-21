# -*- coding: UTF-8 -*-
import pcap
import dpkt
from dpkt import Error

from datetime import *


#列出所有网卡
EthList = pcap.lookupdev()
print EthList

#打开网卡
pc=pcap.pcap("eth1")

#设置监听过滤器
pc.setfilter('tcp port 80')

nrecv,ndrop,nifdrop=pc.stats()

d = {} #hash字典

for time,packet in pc:                                 #ptime为收到时间，pdata为收到数据
        #print "时间 ：" , datetime.fromtimestamp(ptime)
    ethernet_packe = dpkt.ethernet.Ethernet(packet)     #解析以太网包  第一层结构
        #以太网包属性  源MAC.dst              目标MAC.src            下层协议类型.type（IP 0x0800）
    if ethernet_packe.data.__class__.__name__ == "IP":
        ip_packet = ethernet_packe.data                 #这是一个IP包  第二层结构
        #IP包属性      版本、头长.v_hl        区分服务.tos           长度.len
        #              Identification.id      Fragment offset.off    Time to live.ttl
        #              下层协议.p(6 TCO)      校验和.sum             源ip.src         目的ip.dst
        src = "%d.%d.%d.%d" % tuple(map(ord, list(ip_packet.src)))
        dst = "%d.%d.%d.%d" % tuple(map(ord, list(ip_packet.dst)))
        if ip_packet.data.__class__.__name__ == "TCP":
            tcpacket = ip_packet.data                   #这是一个TCP包 第三层结构
        #TCP包属性     源端口.sport(http80)   目的端口.dport(http80) 相关序列号.seq
        #              相关响应号.ack         头长.off_x2            标志位.flags
        #              缓冲区大小.win         校验和.sum
            http = tcpacket.data                       #这是一个HTTP包 第四层结构
            if http != None and http != '' and len(http) > 5:    #有效
                try:
                    if tcpacket.dport == 80:
                        Request = dpkt.http.Request(http)             #这是一个请求包
                        x = dst + str(tcpacket.ack)                   #将目的地址ip和ack作为hash键值
                        d[x] = Request
                    elif tcpacket.sport == 80:
                        Requested = dpkt.http.Response(http)          #这是一个回应包
                        x = src + str(tcpacket.seq)                   #将目的源ip和seq作为hash键值
                        if x in d:                                    #配对完成
                            Request = d[x]
                            print "============================================================================="
                            print src, '<--->' ,dst
                            print "-----------------------------------------------------------------------------"
                            print Request.show()
                            print "-----------------------------------------------------------------------------"
                            print Requested.show()

                            del d[x]
                        else:
                            print "?============================================================================"
                            print src, '<--->' ,dst
                            print Requested.show()
                except Error:
                    pass   #解包错误