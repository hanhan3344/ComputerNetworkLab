#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // 初始化发送缓冲区
    uint16_t data_len = req_buf->len;
    buf_t txbuf;
    buf_init(&txbuf, data_len);

    // 将数据拷贝到发送缓冲区
    buf_copy(&txbuf, req_buf, data_len);

    // 封装ICMP报头
    icmp_hdr_t *req_icmp_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr_t *icmp_header = (icmp_hdr_t *)txbuf.data;
    icmp_header->type = ICMP_TYPE_ECHO_REPLY;
    icmp_header->code = 0;
    icmp_header->checksum16 = 0;
    icmp_header->id16 = req_icmp_hdr->id16;
    icmp_header->seq16 = req_icmp_hdr->seq16;

    // 计算ICMP报头校验和
    icmp_header->checksum16 = checksum16((uint16_t *)icmp_header, txbuf.len);

    // 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(icmp_hdr_t)) {
        // 接收到的包长小于ICMP头部长度
        return;
    }

    icmp_hdr_t *icmphdr = (icmp_hdr_t *)buf->data;

    if (icmphdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // 是回显请求
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // 初始化txbuf
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);
    // 填写ICMP报头首部
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->seq16 = 0;
    icmp_hdr->id16 = 0;

    icmp_hdr->checksum16 = checksum16((uint16_t *) icmp_hdr, txbuf.len);

    // 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}