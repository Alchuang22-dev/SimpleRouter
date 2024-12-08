/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

// 由于时间限制，未启用头的解析模式
bool SimpleRouter::parseEthernetHeader(const Buffer& packet, ParsedEthernetHeader& parsed_eth_hdr) {
    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "Packet too short for Ethernet header." << std::endl;
        return false;
    }
    std::memcpy(&parsed_eth_hdr.eth_hdr, packet.data(), sizeof(ethernet_hdr));
    return true;
}

// 解析 ARP 头
bool SimpleRouter::parseArpHeader(const Buffer& packet, ParsedArpHeader& parsed_arp_hdr) {
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) {
        std::cerr << "Packet too short for ARP header." << std::endl;
        return false;
    }
    std::memcpy(&parsed_arp_hdr.header, packet.data() + sizeof(ethernet_hdr), sizeof(arp_hdr));
    return true;
}

// 解析 IPv4 头
bool SimpleRouter::parseIpHeader(const Buffer& packet, ParsedIpHeader& parsed_ip_hdr) {
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
        std::cerr << "Packet too short for IP header." << std::endl;
        return false;
    }
    ip_hdr temp_ip;
    std::memcpy(&temp_ip, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
    size_t ip_header_length = temp_ip.ip_hl * 4;
    if (ip_header_length < sizeof(ip_hdr)) {
        std::cerr << "Invalid IP header length." << std::endl;
        return false;
    }
    if (packet.size() < sizeof(ethernet_hdr) + ip_header_length) {
        std::cerr << "Packet too short for full IP header." << std::endl;
        return false;
    }
    std::memcpy(&parsed_ip_hdr.header, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
    parsed_ip_hdr.header_length = ip_header_length;
    return true;
}


void SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling ARP packet" << std::endl;
  
  // 检查ARP包的有效性
  arp_hdr* arp_ptr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
  
  // 检查包长度
  if (packet.size() != sizeof(arp_hdr) + sizeof(ethernet_hdr)) {
    std::cout << "ARP header has insufficient length, ignoring." << std::endl;
    return;
  }
  
  // 检查硬件类型
  if (ntohs(arp_ptr->arp_hrd) != arp_hrd_ethernet) {
    std::cout << "ARP hardware type is not ethernet, ignoring." << std::endl;
    return;
  }
  
  // 检查协议类型
  if (ntohs(arp_ptr->arp_pro) != ethertype_ip) {
    std::cout << "ARP protocol type is not IPv4, ignoring." << std::endl;
    return;
  }
  
  // 检查硬件地址长度
  if (arp_ptr->arp_hln != ETHER_ADDR_LEN) {
    std::cout << "ARP hardware has invalid address length, ignoring." << std::endl;
    return;
  }
  
  // 检查协议地址长度
  if (arp_ptr->arp_pln != 0x04) {
    std::cout << "ARP protocol has invalid address length, ignoring." << std::endl;
    return;
  }
  
  // 检查ARP操作码
  uint16_t arp_op = ntohs(arp_ptr->arp_op);
  if (arp_op != arp_op_request && arp_op != arp_op_reply) {
    std::cout << "ARP opcode is neither request nor reply, ignoring." << std::endl;
    return;
  }
  
  // 处理ARP请求或ARP应答
  if (arp_op == arp_op_request) {
    handleArpRequest(packet, inIface);
  } else {  // arp_op_reply
    handleArpReply(packet, inIface);
  }
}


void SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface){
    std::cout << "Handling ARP request" << std::endl;
  
    // 获取以太网头和 ARP 头
    ethernet_hdr* eth_ptr = (struct ethernet_hdr*)(packet.data());
    arp_hdr* arp_ptr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
  
    // 打印 ARP 请求的发送者信息
    Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + ETHER_ADDR_LEN);  // 转换为 Buffer 类型
    std::cout << "Received ARP request from IP: " << arp_ptr->arp_sip << ", MAC: " << macToString(sender_mac) << std::endl;

    // ARP 回复
    Buffer reply(packet);
    ethernet_hdr* rep_eth = (ethernet_hdr*)reply.data();
    arp_hdr* rep_arp = (arp_hdr*)(reply.data() + sizeof(ethernet_hdr));
    
    // 查找接口
    const Interface* iface = findIfaceByName(inIface);
    
    // 确保 ARP 请求的目标是本机
    if (arp_ptr->arp_tip != iface->ip) {
        std::cout << "ARP request is not for this router, ignoring." << std::endl;
        return;
    }

    // 设置以太网头
    std::memcpy(rep_eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
    std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
    rep_eth->ether_type = htons(ethertype_arp);

    // 设置 ARP 回复
    rep_arp->arp_hrd = htons(0x0001);  // Ethernet
    rep_arp->arp_pro = htons(0x0800);  // IPv4
    rep_arp->arp_hln = 6;  // MAC 地址长度
    rep_arp->arp_pln = 4;  // IPv4 地址长度
    rep_arp->arp_op = htons(0x0002);  // ARP reply
    rep_arp->arp_sip = iface->ip;  // 回复源 IP（本机的 IP）
    rep_arp->arp_tip = arp_ptr->arp_sip;  // 请求中的目标 IP（发送者的 IP）
    std::memcpy(rep_arp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);  // 本机的 MAC
    std::memcpy(rep_arp->arp_tha, arp_ptr->arp_sha, ETHER_ADDR_LEN);  // 请求中的源 MAC

    // 发送 ARP 回复包
    sendPacket(reply, inIface);
}



void SimpleRouter::handleArpReply(const Buffer& packet, const std::string& inIface) {
  std::cout << "Handling ARP reply" << std::endl;
  
  arp_hdr* arp_ptr = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  uint32_t sender_ip = arp_ptr->arp_sip;
  
  // 创建 Buffer 对象
  Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + 6);
  
  // 打印 MAC 地址和 IP
  std::cout << "Received ARP reply: IP: " << ntohl(sender_ip) << " MAC: " 
            << macToString(sender_mac) << std::endl;
  
  // 处理 IP/MAC 配对
  auto arp_entry = m_arp.lookup(sender_ip);
  if (!arp_entry) {
    auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);
    if (arp_req) {
      std::cout << "Processing queued packets for IP/MAC pair" << std::endl;
      for (const auto& packet : arp_req->packets) {
        handlePacket(packet.packet, packet.iface);
      }
      m_arp.removeRequest(arp_req);
    } else {
      std::cout << "No queued requests for this IP/MAC pair" << std::endl;
    }
  } else {
    std::cout << "IP/MAC pair already exists in ARP table, ignoring." << std::endl;
  }
}



void SimpleRouter::sendArpRequest(uint32_t ip) {
  std::cout << "Sending ARP Request for IP: " << ntohl(ip) << std::endl;

  Buffer req(sizeof(ethernet_hdr) + sizeof(arp_hdr));
  const RoutingTableEntry entry = m_routingTable.lookup(ip);
  const Interface* outIface = findIfaceByName(entry.ifName);
  const Buffer BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  // 构建以太网头
  ethernet_hdr* eth_ptr = (ethernet_hdr*)(req.data());
  std::memcpy(eth_ptr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(eth_ptr->ether_dhost, BROADCAST_ADDR.data(), ETHER_ADDR_LEN);
  eth_ptr->ether_type = htons(ethertype_arp);

  // 构建ARP请求
  arp_hdr* req_arp = (arp_hdr*)(req.data() + sizeof(ethernet_hdr));
  req_arp->arp_hrd = htons(0x0001);
  req_arp->arp_pro = htons(0x0800);
  req_arp->arp_hln = 6;
  req_arp->arp_pln = 4;
  req_arp->arp_op = htons(arp_op_request);
  req_arp->arp_sip = outIface->ip;
  req_arp->arp_tip = ip;
  std::memcpy(req_arp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(req_arp->arp_tha, BROADCAST_ADDR.data(), ETHER_ADDR_LEN);
    
  // 发送ARP请求
  sendPacket(req, outIface->name);
}


void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling IPv4 packet" << std::endl;
  
  // Check if the packet is large enough to contain both Ethernet and IP headers
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cout << "IP header has insufficient length, ignoring." << std::endl;
    return;
  }
  
  // Get IP header pointer, safely check bounds
  ip_hdr* ip_ptr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
  
  // Check if the IP pointer is valid (not null, within bounds)
  if (ip_ptr == nullptr || packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + ip_ptr->ip_hl * 4) {
    std::cout << "Invalid IP header or insufficient packet length, ignoring." << std::endl;
    return;
  }

  // Compute the IP header length
  uint8_t ip_header_length = ip_ptr->ip_hl * 4;
  if (ip_header_length < sizeof(ip_hdr)) {
    std::cout << "Invalid IP header length, ignoring." << std::endl;
    return;
  }

  std::cout << "IP Header Length: " << static_cast<int>(ip_header_length) << " bytes" << std::endl;
  
  // Validate checksum
  uint16_t computed_checksum = cksum(ip_ptr, ip_header_length);
  std::cout << "Computed Checksum: " << std::hex << computed_checksum << std::dec << std::endl;
  
  // Compare checksum to 0xFFFF (standard checksum check for IP headers)
  if (computed_checksum != 0xFFFF) {
    std::cout << "IP header checksum is invalid, ignoring." << std::endl;
    return;
  }

  // Classify datagrams by destination
  const Interface* destIface = findIfaceByIp(ip_ptr->ip_dst);
  if (destIface != nullptr) {  // Packet is destined for the router
    std::cout << "IP packet destined for the router." << std::endl;
    
    // Check if the protocol is ICMP
    if (ip_ptr->ip_p == ip_protocol_icmp) {
      std::cout << "Handling ICMP packet." << std::endl;
      handleICMP(packet, inIface);
    }
    // Check if the protocol is TCP (0x06) or UDP (0x11)
    else if (ip_ptr->ip_p == 0x06 || ip_ptr->ip_p == 0x11) {
      std::cout << "Handling Port Unreachable ICMP response." << std::endl;
      handleICMPPortUnreachable(packet, inIface);
    }
    else {
      std::cout << "Unsupported protocol, ignoring." << std::endl;
    }
  } else {  // Packet to be forwarded
    std::cout << "Datagram to be forwarded." << std::endl;

    // Time-to-live (TTL) check
    if (ip_ptr->ip_ttl == 1 || ip_ptr->ip_ttl == 0) {  // TTL expired
      std::cout << "Sending Time Exceeded ICMP message." << std::endl;
      handleICMPTimeExceeded(packet, inIface);
    } else {
      std::cout << "Forwarding IPv4 packet." << std::endl;
      forwardIPv4(packet, inIface);
    }
  }
}


void SimpleRouter::forwardIPv4(const Buffer& packet, const std::string& inIface) {
    std::cout << "Forwarding IPv4 packet" << std::endl;

    // 提取 IP header
    ip_hdr* ip_ptr = reinterpret_cast<ip_hdr*>(const_cast<unsigned char*>(packet.data()) + sizeof(ethernet_hdr));

    // 查找路由表条目
    auto routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
    
    // 查找 ARP 表条目
    std::cout << "Forwarding packet to: " << ntohl(ip_ptr->ip_dst) << " via " << routing_entry.ifName << std::endl;
    auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);
    std::cout << "Looking for ARP entry for IP: " << ntohl(ip_ptr->ip_dst) << std::endl;
    
    if (arp_entry == nullptr) {
        std::cout << "ARP entry not found, queuing ARP request" << std::endl;
        // 将 ARP 请求加入队列
        auto arp_request = m_arp.queueRequest(ip_ptr->ip_dst, packet, inIface);
        if (arp_request) {
            std::cout << "ARP request queued for IP: " << ntohl(ip_ptr->ip_dst) << std::endl;
        } else {
            std::cerr << "Failed to queue ARP request for IP: " << ntohl(ip_ptr->ip_dst) << std::endl;
        }
        return;  // 等待 ARP 请求响应
    }

    std::cout << "ARP Table: ";
    for (const auto& entry : m_arp.getCacheEntries()) {
        std::cout << "ARP Entry - IP: " << ntohl(entry->ip) << " MAC: " << entry->mac.data() << std::endl;
    }
    
    std::cout << "ARP entry MAC for destination IP: " << ntohl(ip_ptr->ip_dst) << " is " << arp_entry->mac.data() << std::endl;

    // 根据路由表获取输出接口
    const Interface* outIface = findIfaceByName(routing_entry.ifName);

    // 准备转发数据包
    Buffer forward(packet);
    ethernet_hdr* fwd_eth = reinterpret_cast<ethernet_hdr*>(forward.data());
    std::memcpy(fwd_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
    std::memcpy(fwd_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

    // 修改 IP 头
    ip_hdr* fwd_ip = reinterpret_cast<ip_hdr*>(forward.data() + sizeof(ethernet_hdr));
    fwd_ip->ip_ttl--;
    fwd_ip->ip_sum = 0;
    fwd_ip->ip_sum = cksum(reinterpret_cast<uint8_t*>(fwd_ip), sizeof(ip_hdr));

    // 打印路由条目信息
    std::cout << "Routing Entry Found: Dest=" << ntohl(routing_entry.dest)
              << ", Gateway=" << ntohl(routing_entry.gw)
              << ", Interface=" << routing_entry.ifName << std::endl;

    // 确定下一跳 IP 地址
    uint32_t next_hop_ip = (routing_entry.gw != 0) ? routing_entry.gw : ip_ptr->ip_dst;

    // 查找 ARP 表中的下一跳 MAC 地址
    arp_entry = m_arp.lookup(next_hop_ip);
    if (arp_entry == nullptr) {
        std::cerr << "ARP entry not found for next hop IP: " << next_hop_ip << std::endl;
        return; // 如果 ARP 表中没有找到下一跳的 MAC 地址，无法继续
    }

    // 发送数据包
    sendPacket(forward, routing_entry.ifName);

    std::cout << "Packet forwarded to " << next_hop_ip << " via " << routing_entry.ifName << std::endl;
}


void SimpleRouter::handleICMP(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP packet" << std::endl;
  
  // Check if the packet is large enough to contain the Ethernet, IP, and ICMP headers
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)) {
    std::cout << "ICMP packet has insufficient length, ignoring." << std::endl;
    return;
  }

  // Get pointer to the ICMP header and perform pointer validity checks
  icmp_hdr* icmp_ptr = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  if (icmp_ptr == nullptr) {
    std::cout << "ICMP header pointer is invalid, ignoring." << std::endl;
    return;
  }

  // Ensure the ICMP type is an Echo Request (type 8, code 0)
  if (icmp_ptr->icmp_type != 0x08 || icmp_ptr->icmp_code != 0x00) {
    std::cout << "ICMP type is not Echo Request, ignoring." << std::endl;
    return;
  }

  // Validate ICMP checksum
  uint16_t icmp_checksum = cksum((uint8_t*)icmp_ptr, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));
  if (icmp_checksum != 0xFFFF) {
    std::cout << "ICMP checksum is invalid, ignoring." << std::endl;
    return;
  }

  // Call handleEchoReply function if all checks pass
  handleEchoReply(packet, inIface);
}

void SimpleRouter::handleICMPt3(const Buffer& packet, const std::string& inIface, uint8_t type, uint8_t code){
  std::cout << "Handling ICMP Type " << (int)type << " Code " << (int)code << " packet" << std::endl;

  // Check if the packet has the minimum size for Ethernet and IP headers
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cout << "Packet is too small to process, ignoring." << std::endl;
    return;
  }

  // Get pointers to Ethernet and IP headers
  ethernet_hdr* eth_ptr = (ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  if (eth_ptr == nullptr || ip_ptr == nullptr) {
    std::cout << "Invalid Ethernet or IP header, ignoring." << std::endl;
    return;
  }

  // Prepare the reply packet buffer
  Buffer reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  const Interface* outIface = findIfaceByName(inIface);

  if (outIface == nullptr) {
    std::cout << "Output interface not found, ignoring." << std::endl;
    return;
  }

  // Populate Ethernet header for the reply
  ethernet_hdr *rep_eth = (ethernet_hdr*)reply.data();
  memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);  // Destination MAC
  memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);  // Source MAC
  rep_eth->ether_type = htons(ethertype_ip);

  // Populate IP header for the reply
  ip_hdr *rep_ip = (ip_hdr*)(reply.data() + sizeof(ethernet_hdr));
  memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));  // Copy original IP header
  rep_ip->ip_tos = 0;
  rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  rep_ip->ip_id = 0;
  rep_ip->ip_ttl = 64;
  rep_ip->ip_p = ip_protocol_icmp;
  rep_ip->ip_sum = 0;
  rep_ip->ip_src = outIface->ip;
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

  // Populate ICMP Type 3 header for the reply
  icmp_t3_hdr *rep_icmpt3 = (icmp_t3_hdr*)(reply.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  rep_icmpt3->icmp_type = type;
  rep_icmpt3->icmp_code = code;
  rep_icmpt3->icmp_sum = 0;
  rep_icmpt3->next_mtu = 0;
  rep_icmpt3->unused = 0;
  std::memcpy(rep_icmpt3->data, ip_ptr, ICMP_DATA_SIZE);  // Copy part of the IP header to ICMP data
  rep_icmpt3->icmp_sum = cksum(rep_icmpt3, sizeof(icmp_t3_hdr));  // Calculate ICMP checksum

  // Send the reply packet
  sendPacket(reply, inIface);
}

void SimpleRouter::handleICMPPortUnreachable(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP Port Unreachable packet" << std::endl;
  handleICMPt3(packet, inIface, 3, 3);
}

void SimpleRouter::handleICMPTimeExceeded(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP Time Exceeded packet" << std::endl;
  handleICMPt3(packet, inIface, 11, 0);
}

void SimpleRouter::handleICMPHostUnreachable(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP Host Unreachable packet" << std::endl;
  handleICMPt3(packet, inIface, 3, 1);
}


void SimpleRouter::handleEchoReply(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling Echo Reply packet" << std::endl;

  // Check if the packet is large enough to contain Ethernet, IP, and ICMP headers
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)) {
    std::cout << "Echo Reply packet has insufficient length, ignoring." << std::endl;
    return;
  }

  // Get pointers to Ethernet and IP headers
  ethernet_hdr* eth_ptr = (ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  if (eth_ptr == nullptr || ip_ptr == nullptr) {
    std::cout << "Invalid Ethernet or IP header, ignoring." << std::endl;
    return;
  }

  // Prepare the reply packet
  Buffer reply(packet); // Copy the original packet to modify it

  // Ethernet header
  ethernet_hdr* rep_eth = (ethernet_hdr*)((uint8_t*)reply.data());
  std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);  // Destination MAC
  std::memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);  // Source MAC
  rep_eth->ether_type = htons(ethertype_ip);

  // IP header
  ip_hdr* rep_ip = (ip_hdr*)((uint8_t*)reply.data() + sizeof(ethernet_hdr));
  rep_ip->ip_id = 0;  // Clear the ID
  rep_ip->ip_src = ip_ptr->ip_dst;  // Swap the source and destination IPs
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_ttl = 64;  // Set TTL to 64 for the reply
  rep_ip->ip_sum = 0;  // Reset checksum before recalculating
  rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));  // Recalculate IP checksum

  // ICMP header
  icmp_hdr* rep_icmp = (icmp_hdr*)((uint8_t*)reply.data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
  rep_icmp->icmp_type = 0x00;  // Set ICMP type to Echo Reply (0)
  rep_icmp->icmp_code = 0x00;  // Set ICMP code to 0
  rep_icmp->icmp_sum = 0;  // Reset checksum before recalculating
  rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, reply.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));  // Recalculate ICMP checksum

  // Log the details of the reply
  std::cout << "Echo Reply: src_ip=" << rep_ip->ip_src << ", dst_ip=" << rep_ip->ip_dst << std::endl;
  std::cout << "ICMP Type: " << static_cast<int>(rep_icmp->icmp_type) << ", Code: " << static_cast<int>(rep_icmp->icmp_code) << std::endl;

  // Send the reply packet
  sendPacket(reply, inIface);
}


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  // Check if interface exists
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << "Routing Table:\n" << getRoutingTable() << std::endl;

  // Check the validity of Ethernet header
  if (packet.size() < sizeof(ethernet_hdr)) {
    std::cout << "Ethernet header has insufficient length, ignored." << std::endl;
    return;
  }

  // Extract Ethernet header and check the type
  ethernet_hdr* eth_hdr = (ethernet_hdr*)packet.data();
  uint16_t eth_type = ethertype((uint8_t*)eth_hdr);

  // Check supported Ethernet types
  if (eth_type != ethertype_ip && eth_type != ethertype_arp) {
    std::cout << "Extracted Ethernet Type: 0x" << std::hex << eth_type << std::dec << std::endl;
    std::cout << "Ethernet frame has unsupported type, ignored." << std::endl;
    return;
  }

  // Check destination address (either router's interface MAC or broadcast)
  bool valid_dest = false;
  if (std::memcmp(eth_hdr->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN) == 0) {
    std::cout << "Destination is the router's interface MAC address." << std::endl;
    valid_dest = true;
  } else if (std::all_of(eth_hdr->ether_dhost, eth_hdr->ether_dhost + 6, [](uint8_t a) { return a == 0xff; })) {
    std::cout << "Destination is the broadcast address." << std::endl;
    valid_dest = true;
  } else {
    std::cout << "Destination address is invalid, ignoring." << std::endl;
  }

  if (!valid_dest) {
    std::cerr << "Packet with invalid destination address, ignoring." << std::endl;
    return;
  }

  // Handle packet based on Ethernet type
  try {
    if (eth_type == ethertype_arp) {
      std::cout << "Handling ARP packet" << std::endl;
      handleArp(packet, inIface);
    }
    else if (eth_type == ethertype_ip) {
      std::cout << "Handling IPv4 packet" << std::endl;
      handleIPv4(packet, inIface);
    } else {
      std::cerr << "Unhandled Ethernet type: " << std::hex << eth_type << std::dec << ", ignoring." << std::endl;
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Exception occurred while handling packet: " << e.what() << std::endl;
  }
  catch (...) {
    std::cerr << "Unknown error occurred while handling packet." << std::endl;
  }
}


void SimpleRouter::printRoutingTable() const {
    std::cout << "Current Routing Table:" << std::endl;
    std::cout << m_routingTable << std::endl; // 使用 operator<< 重载打印路由表
}

std::string SimpleRouter::BufferToMAC(const Buffer& buffer) const {
    std::ostringstream oss;
    for(size_t i = 0; i < buffer.size(); ++i){
        if(i != 0)
            oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    return oss.str();
}

void SimpleRouter::printIfaces(std::ostream& os) const {
    os << "Current Interface Configurations:" << std::endl;
    for(const auto& iface : m_ifaces){
        os << "Interface: " << iface.name 
           << ", IP: " << iface.ip 
           << ", MAC: " << BufferToMAC(iface.addr) << std::endl;
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  printRoutingTable();
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
  printIfaces(std::cout);
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
