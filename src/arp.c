#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    buf_init(&txbuf, sizeof(arp_pkt_t)); //调用buf_init()对txbuf进行初始化。
    arp_pkt_t arp_pkt01 = arp_init_pkt;
    // 填写ARP报头。
    arp_pkt01.hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt01.pro_type16 = swap16(NET_PROTOCOL_IP);
    arp_pkt01.hw_len = NET_MAC_LEN;
    arp_pkt01.pro_len = NET_IP_LEN;
    arp_pkt01.opcode16 = swap16(ARP_REQUEST); //ARP操作类型为ARP_REQUEST，注意大小端转换。
    memcpy(arp_pkt01.sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp_pkt01.sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt01.target_ip, target_ip, NET_IP_LEN);

    memcpy(txbuf.data, &arp_pkt01, sizeof(arp_pkt_t));
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP); //调用ethernet_out函数将ARP报文发送出去。注意：ARP announcement或ARP请求报文都是广播报文，其目标MAC地址应该是广播地址：FF-FF-FF-FF-FF-FF。
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    buf_init(&txbuf, sizeof(arp_pkt_t)); //首先调用buf_init()来初始化txbuf。
    arp_pkt_t arp_pkt01 = arp_init_pkt;
    //接着，填写ARP报头首部。
    arp_pkt01.hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt01.pro_type16 = swap16(NET_PROTOCOL_IP);
    arp_pkt01.hw_len = NET_MAC_LEN;
    arp_pkt01.pro_len = NET_IP_LEN;
    arp_pkt01.opcode16 = swap16(ARP_REPLY);
    memcpy(arp_pkt01.sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp_pkt01.sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt01.target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt01.target_mac, target_mac, NET_MAC_LEN);

    memcpy(txbuf.data, &arp_pkt01, sizeof(arp_pkt_t));

    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP); //调用ethernet_out()函数将填充好的ARP报文发送出去。
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    if(buf->len < sizeof(arp_pkt_t)){ //首先判断数据长度，如果数据长度小于ARP头部长度，则认为数据包不完整，丢弃不处理。
        return;
    }else{
        arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
        //接着，做报头检查，查看报文是否完整，检测内容包括：ARP报头的硬件类型、上层协议类型、MAC硬件地址长度、IP协议地址长度、操作类型，检测该报头是否符合协议规定。
        if(arp_pkt->hw_type16 != swap16(ARP_HW_ETHER) ||
        arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        arp_pkt->hw_len != NET_MAC_LEN ||
        arp_pkt->pro_len != NET_IP_LEN ||
        (arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY))){
            return;
        }
        map_set(&arp_table, arp_pkt->sender_ip, src_mac); //调用map_set()函数更新ARP表项。

        buf_t *arp_buf01 = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip); //调用map_get()函数查看该接收报文的IP地址是否有对应的arp_buf缓存。
        if(arp_buf01 != NULL){ //如果有，则说明ARP分组队列里面有待发送的数据包。也就是上一次调用arp_out()函数发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文，此时收到了该request的应答报文。
            ethernet_out(arp_buf01, arp_pkt->sender_mac, NET_PROTOCOL_IP); //然后，将缓存的数据包arp_buf再发送给以太网层，即调用ethernet_out()函数直接发出去
            map_delete(&arp_buf, arp_pkt->sender_ip); //接着调用map_delete()函数将这个缓存的数据包删除掉。
        }else if(arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0){ //接着调用map_delete()函数将这个缓存的数据包删除掉。
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac); //调用arp_resp()函数回应一个响应报文
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    uint8_t *target_mac = (uint8_t *)map_get(&arp_table, ip); //调用map_get()函数，根据IP地址来查找ARP表(arp_table)。
    if(target_mac != NULL){ //如果能找到该IP地址对应的MAC地址，则将数据包直接发送给以太网层，即调用ethernet_out函数直接发出去。
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
        return;
    }else if(map_get(&arp_buf, ip)==NULL){ //如果没有找到对应的MAC地址，进一步判断arp_buf是否已经有包了，如果有，则说明正在等待该ip回应ARP请求，此时不能再发送arp请求；如果没有包，则调用map_set()函数将来自IP层的数据包缓存到arp_buf，然后，调用arp_req()函数，发一个请求目标IP地址对应的MAC地址的ARP request报文。
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL); //调用map_init()函数，初始化用于存储IP地址和MAC地址的ARP表arp_table，并设置超时时间为ARP_TIMEOUT_SEC。
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy); //调用map_init()函数，初始化用于缓存来自IP层的数据包，并设置超时时间为ARP_MIN_INTERVAL。
    net_add_protocol(NET_PROTOCOL_ARP, arp_in); //调用net_add_protocol()函数，增加key：NET_PROTOCOL_ARP和vaule：arp_in的键值对。
    arp_req(net_if_ip); //在初始化阶段（系统启用网卡）时，要向网络上发送无回报ARP包（ARP announcemennt），即广播包，告诉所有人自己的IP地址和MAC地址。在实验代码中，调用arp_req()函数来发送一个无回报ARP包。
}
