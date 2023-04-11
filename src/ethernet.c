#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    if(buf->len < sizeof(ether_hdr_t)){
        printf("Oooooooops! The data length is less than the Ethernet header length. Error!\n");
        return;
    }
    ether_hdr_t *eth_hdr = (ether_hdr_t *)buf->data;
    if(buf_remove_header(buf, sizeof(ether_hdr_t)) < 0){
        printf("Oooooooops! buf_remove_header error!\n");
        return;
    }
    
    uint16_t protoc = swap16(eth_hdr->protocol16);
    if(net_in(buf, protoc, eth_hdr->src) < 0){
        printf("Oooooooops! net_in error!\n");
        return;
    }
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT){
        if(buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len) < 0){
            printf("Oooooooops! buf_add_padding error!\n");
            return;
        }
    }
    if(buf_add_header(buf, sizeof(ether_hdr_t)) < 0){
        printf("Oooooooops! buf_add_header error!\n");
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);

    if(driver_send(buf) < 0){
        printf("Oooooooops! driver_send error!\n");
        return;
    }
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
