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

void SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP packet" << std::endl;
  // check the validity of arp header
  arp_hdr* arp_ptr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
  // size
  if (packet.size() != sizeof(arp_hdr) + sizeof(ethernet_hdr)){
    std::cout<< "ARP header has insufficient length, ignoring." << std::endl;
    return;
  }
  // hardware type
  if(ntohs(arp_ptr->arp_hrd) != arp_hrd_ethernet){
    std::cout<< "ARP hardware type is not ethernet, ignoring." << std::endl;
    return;
  }
  // protocol type
  if(ntohs(arp_ptr->arp_pro) != ethertype_ip){
    std::cout<< "ARP protocol type is not IPv4, ignoring." << std::endl;
    return;
  }
  // hardware addr len
  if(arp_ptr->arp_hln != ETHER_ADDR_LEN){
    std::cout<< "ARP hardware has invalid address length, ignoring." << std::endl;
    return;
  }

  // proto len
  if(arp_ptr->arp_pln != 0x04){
    std::cout<< "ARP protocol has invalid address length, ignoring." << std::endl;
    return;
  }
  // opcode
  if(ntohs(arp_ptr->arp_op) != arp_op_request && ntohs(arp_ptr->arp_op) != arp_op_reply){
    std::cout<< "ARP opcode is neither request nor reply, ignoring." << std::endl;
    return;
  }
  // handle request or reply
  // request
  if(ntohs(arp_ptr->arp_op) == arp_op_request){
    handleArpRequest(packet, inIface);
  }
  // reply
  else{
    handleArpReply(packet, inIface);
  }
}

void SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP request" << std::endl;
  
  // ARP request
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)(packet.data());
  arp_hdr* arp_ptr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
  std::cout << "Received ARP request from IP: " << arp_ptr->arp_sip << ", MAC: " << arp_ptr->arp_sha << std::endl;
  // ARP reply
  Buffer reply(packet);
  ethernet_hdr* rep_eth = (ethernet_hdr*)reply.data();
  arp_hdr* rep_arp = (arp_hdr*)(reply.data() + sizeof(ethernet_hdr));
  
  // update params
  const Interface* iface = findIfaceByName(inIface);
  if(arp_ptr->arp_tip != iface->ip){
    std::cout << "Arp destination is not the router, ignoring." << std::endl;
    return;
  }
  // ethernet
  std::memcpy(rep_eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  rep_eth->ether_type = htons(ethertype_arp);

  // arp
  rep_arp->arp_hrd = htons(0x0001);
  rep_arp->arp_pro = htons(0x0800);
  rep_arp->arp_hln = 6;
  rep_arp->arp_pln = 4;
  rep_arp->arp_op = htons(0x0002);
  rep_arp->arp_sip = iface->ip;
  rep_arp->arp_tip = arp_ptr->arp_sip;
  std::memcpy(rep_arp->arp_sha, iface->addr.data(), 6);
  std::memcpy(rep_arp->arp_tha, arp_ptr->arp_sha, 6);

  // send reply
  sendPacket(reply, inIface);
}

void SimpleRouter::handleArpReply(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP reply" << std::endl;

  arp_hdr* arp_ptr = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));
  uint32_t sender_ip = arp_ptr->arp_sip;
  Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + 6);
  std::cout << "Received ARP request from IP: " << arp_ptr->arp_sip << ", MAC: " << arp_ptr->arp_sha << std::endl;
  std::cout << "Received ARP reply: IP: " << ntohl(sender_ip) << " MAC: " << sender_mac.data() << std::endl;
  // pairing IP/MAC
  if (!m_arp.lookup(sender_ip)) {
    auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);
    if (arp_req) {
      std::cout << "Handle queued requests for the IP/MAC" << std::endl;
      for (const auto& packet : arp_req->packets) {
        handlePacket(packet.packet, packet.iface);
      }
      m_arp.removeRequest(arp_req);
      } else {
        std::cout << "No queued requests for the IP/MAC" << std::endl;
      }
    } else {
      std::cout << "IP/MAC already exists, ignoring." << std::endl;
    }
}

void SimpleRouter::sendArpRequest(uint32_t ip){
  std::cout << "Sending Arp Request" << std::endl;
  std::cout << "Sending ARP request for IP: " << ntohl(ip) << std::endl;

  Buffer req(sizeof(ethernet_hdr) + sizeof(arp_hdr));
  // look up the routing table
  const RoutingTableEntry entry = m_routingTable.lookup(ip);
  const Interface* outIface = findIfaceByName(entry.ifName);
  const Buffer BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  // handle ethernet header
  ethernet_hdr* eth_ptr = (ethernet_hdr*)(req.data());
  memcpy(eth_ptr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  memcpy(eth_ptr->ether_dhost, BROADCAST_ADDR.data(), ETHER_ADDR_LEN);
  eth_ptr->ether_type = htons(ethertype_arp);

  // handle ARP
  arp_hdr* req_arp = (arp_hdr*)(req.data() + sizeof(ethernet_hdr));
  req_arp->arp_hrd = htons(0x0001);
  req_arp->arp_pro = htons(0x0800);
  req_arp->arp_hln = 0x06;
  req_arp->arp_pln = 0x04;
  req_arp->arp_op = htons(arp_op_request);
  req_arp->arp_sip = outIface->ip;
  req_arp->arp_tip = ip;
  memcpy(req_arp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  memcpy(req_arp->arp_tha, BROADCAST_ADDR.data(), ETHER_ADDR_LEN);
    
  // send request
  sendPacket(req, outIface->name);
}

void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling IPv4 packet" << std::endl;
  // check the validity of ip header
  ip_hdr* ip_ptr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
  // size
  if(packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)){
    std::cout<< "IP header has insufficient length, ignoring." << std::endl;
    return;
  }
  // checksum
  uint8_t ip_header_length = ip_ptr->ip_hl * 4; // 计算 IP 头部长度
  std::cout << "IP Header Length: " << static_cast<int>(ip_header_length) << " bytes" << std::endl;
  std::cout << "Computed Checksum: " << std::hex << cksum(ip_ptr, ip_header_length) << std::dec << std::endl;
  if (cksum(ip_ptr, ip_header_length) != 0xFFFF) {
      std::cout << "IP header checksum is invalid, ignoring." << std::endl;
      return;
  }
  
  // classify datagrams by dest
  const Interface* destIface = findIfaceByIp(ip_ptr->ip_dst);
  if (destIface != nullptr) {// destinated to the router  
    std::cout << "IP packet destinated to the router." << std::endl;
    // ICMP
    if (ip_ptr->ip_p == ip_protocol_icmp) {
      std::cout << "Handle ICMP." << std::endl;
      handleICMP(packet, inIface);
    }
    // TCP & UDP
    else if(ip_ptr->ip_p == 0x0006 || ip_ptr->ip_p == 0x0011){
      std::cout << "Sent Port unreachable." << std::endl;
      handleICMPPortUnreachable(packet, inIface);
    }
    else{
      std::cout << "Unsupported protocol, ignoring" << std::endl;
    }
  }
  else{// to be forwarded
  std::cout << "Datagrams to be forwarded." << std::endl;
    if ((ip_ptr->ip_ttl == 1) || (ip_ptr->ip_ttl == 0)) {// 超时
    std::cout << "Sent time exceeded message." << std::endl;
      handleICMPTimeExceeded(packet, inIface);
    }
    else{
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
  // check the validity of icmp header
  icmp_hdr* icmp_ptr = (struct icmp_hdr*)(packet.data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
  // size
  if(packet.size() < sizeof(icmp_hdr) + sizeof(ip_hdr) + sizeof(ethernet_hdr)){
    std::cout << "ICMP header has insufficient length, ignoring." << std::endl;
    return;
  }
  // type
  if(icmp_ptr->icmp_type != 0x08 || icmp_ptr->icmp_code != 0x00){
    std::cout << "ICMP type is not echo request, ignoring." << std::endl;
    return;
  }
  // checksum
  if (cksum((uint8_t*)icmp_ptr, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr)) != 0xffff) {
    std::cout << "ICMP header checksum is invalid, ignoring." << std::endl;
    return;
  }

  handleEchoReply(packet, inIface);
}

void SimpleRouter::handleICMPt3(const Buffer& packet, const std::string& inIface, uint8_t type, uint8_t code){
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  Buffer reply(sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_t3_hdr));
  const Interface* outIface = findIfaceByName(inIface);

  // ethernet
  ethernet_hdr * rep_eth = (ethernet_hdr *)reply.data();
  memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);
  rep_eth->ether_type = htons(ethertype_ip);

  // ip
  ip_hdr * rep_ip = (ip_hdr *)(reply.data()+sizeof(ethernet_hdr));
  memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));
  rep_ip->ip_tos = 0;
  rep_ip->ip_len = htons(sizeof(ip_hdr)+sizeof(icmp_t3_hdr));
  rep_ip->ip_id  = 0;                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
  rep_ip->ip_ttl = 64;
  rep_ip->ip_p = ip_protocol_icmp;
  rep_ip->ip_sum = 0;
  rep_ip->ip_src = outIface->ip;
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

  // icmp type3
  icmp_t3_hdr * rep_icmpt3 = (struct icmp_t3_hdr *)(reply.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr));
  rep_icmpt3->icmp_type = type;
  rep_icmpt3->icmp_code = code;
  rep_icmpt3->icmp_sum = 0;
  rep_icmpt3->next_mtu = 0;
  rep_icmpt3->unused = 0;
  std::memcpy(rep_icmpt3->data, ip_ptr, ICMP_DATA_SIZE);
  rep_icmpt3->icmp_sum = cksum(rep_icmpt3, sizeof(icmp_t3_hdr));
  
  sendPacket(reply, inIface);
}

void SimpleRouter::handleICMPPortUnreachable(const Buffer& packet,const std::string& inIface){
  std::cout<<"handling ICMP Port Unreachable packet" << std::endl;
  handleICMPt3(packet, inIface, 3, 3);
}

void SimpleRouter::handleICMPTimeExceeded(const Buffer& packet,const std::string& inIface){
  std::cout<<"handling ICMP Time Exceeded packet" << std::endl;
  handleICMPt3(packet, inIface, 11, 0);
}

void SimpleRouter::handleICMPHostUnreachable(const Buffer& packet, const std::string& inIface){
  std::cout<<"handling ICMP Host Unreachable packet" << std::endl;
  handleICMPt3(packet, inIface, 3, 1);
}

void SimpleRouter::handleEchoReply(const Buffer& packet, const std::string& inIface){
  std::cout << "handling Echo Reply packet" << std::endl;
  ethernet_hdr* eth_ptr = (struct ethernet_hdr*)((uint8_t*)packet.data());
  ip_hdr* ip_ptr = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(ethernet_hdr));

  Buffer reply(packet);
  // ethernet header
  ethernet_hdr* rep_eth = (struct ethernet_hdr*)((uint8_t*)reply.data());
  std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  std::memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);
  rep_eth->ether_type = htons(ethertype_ip);

  // ip header
  ip_hdr* rep_ip = (struct ip_hdr*)((uint8_t*)reply.data() + sizeof(ethernet_hdr));
  rep_ip->ip_id = 0;
  rep_ip->ip_src = ip_ptr->ip_dst;
  rep_ip->ip_dst = ip_ptr->ip_src;
  rep_ip->ip_ttl = 64;
  rep_ip->ip_sum = 0;
  rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

  // icmp header
  icmp_hdr* rep_icmp = (struct icmp_hdr*)((uint8_t*)reply.data() + sizeof(ip_hdr) + sizeof(ethernet_hdr));
  rep_icmp->icmp_type = 0x00;
  rep_icmp->icmp_code = 0x00;
  rep_icmp->icmp_sum = 0;
  rep_icmp->icmp_sum = cksum((uint8_t*)rep_icmp, reply.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));

  std::cout << "Echo Reply: src_ip=" << rep_ip->ip_src << ", dst_ip=" << rep_ip->ip_dst << std::endl;
  std::cout << "ICMP Type: " << static_cast<int>(rep_icmp->icmp_type) << ", Code: " << static_cast<int>(rep_icmp->icmp_code) << std::endl;
    
  sendPacket(reply, inIface);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  // check the validity of ethernet header
  // size
  if(packet.size() < sizeof(ethernet_hdr)){
    std::cout<< "Ethernet header has insufficient length, ignored." << std::endl;
    return;
  }
  // type
  ethernet_hdr* eth_hdr = (ethernet_hdr*) packet.data();
  uint16_t eth_type = ethertype((uint8_t*)eth_hdr);
  if(eth_type != ethertype_ip && eth_type != ethertype_arp){
    std::cout << "Extracted Ethernet Type: 0x" << std::hex << eth_type << std::dec << std::endl;
    std::cout<< "Ethernet frame has unsupported type, ignored." << std::endl;
    return;
  }
  // dest addr: router or broadcast
  if (std::memcmp(eth_hdr->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN) == 0) {
    std::cout << "Destination host is the interface MAC address of router" << std::endl;
  }
  else if (std::all_of(eth_hdr->ether_dhost, eth_hdr->ether_dhost + 6, [](uint8_t a) { return a == 0xff; })) {
    std::cout << "Destination host is broadcast address." << std::endl;
  } else {
    // invalid dest
    std::cout << "Destination host is invalid, ignored." << std::endl;
  }

  // handle by type
  if(eth_type == ethertype_arp){
    handleArp(packet, inIface);
  }
  else{
    handleIPv4(packet, inIface);
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
