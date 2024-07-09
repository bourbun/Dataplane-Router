#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/lib.h"
#include "include/protocols.h"
#include "include/queue.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *arp_table;
int arp_table_len;

int comp(const void *a, const void *b) {
  const struct route_table_entry *entry_a = (const struct route_table_entry *)a;
  const struct route_table_entry *entry_b = (const struct route_table_entry *)b;

  uint32_t masked_prefix_a = ntohl(entry_a->mask & entry_a->prefix);
  uint32_t masked_prefix_b = ntohl(entry_b->mask & entry_b->prefix);

  if (masked_prefix_a == masked_prefix_b) {
    return ntohl(entry_a->mask) - ntohl(entry_b->mask);
  } else {
    return masked_prefix_a - masked_prefix_b;
  }
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
  int left = 0;
  int right = rtable_len - 1;
  struct route_table_entry *best_match = NULL;

  while (left <= right) {
    int mid = left + (right - left) / 2;
    struct route_table_entry *current_route = &rtable[mid];

    if ((ip_dest & current_route->mask) == current_route->prefix) {
      best_match = current_route;
      left = mid + 1;
    } else if (ntohl(current_route->prefix) <
               ntohl(ip_dest & current_route->mask)) {
      left = mid + 1;
    } else {
      right = mid - 1;
    }
  }

  return best_match;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
  for (int i = 0; i < arp_table_len; i++) {
    if (given_ip == arp_table[i].ip) return &arp_table[i];
  }

  return NULL;
}

void send_icmp_request(uint32_t ip_dest, const uint8_t *mac_src,
                       const uint8_t *mac_dest, uint8_t type, uint8_t code,
                       const uint8_t *data, size_t data_len, int iface) {
  char packet[MAX_PACKET_LEN];
  struct ether_header *eth_hdr = (struct ether_header *)packet;
  struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
  struct icmphdr *icmp_hdr =
      (struct icmphdr *)(packet + sizeof(struct ether_header) +
                         sizeof(struct iphdr));

  memcpy(eth_hdr->ether_shost, mac_src, 6);
  memcpy(eth_hdr->ether_dhost, mac_dest, 6);
  eth_hdr->ether_type = htons(ETHERTYPE_IP);

  ip_hdr->ihl = 5;
  ip_hdr->version = 4;
  ip_hdr->tos = 0;
  ip_hdr->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);
  ip_hdr->id = htons(1);
  ip_hdr->frag_off = 0;
  ip_hdr->ttl = 64;
  ip_hdr->protocol = IPPROTO_ICMP;
  ip_hdr->saddr = inet_addr(get_interface_ip(iface));
  ip_hdr->daddr = ip_dest;
  ip_hdr->check = 0;
  ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

  icmp_hdr->type = type;
  icmp_hdr->code = code;
  icmp_hdr->checksum = 0;
  memcpy(icmp_hdr + 1, data, data_len);
  icmp_hdr->checksum =
      checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + data_len);

  send_to_link(iface, packet,
               sizeof(struct ether_header) + sizeof(struct iphdr) +
                   sizeof(struct icmphdr) + data_len);
}

int main(int argc, char *argv[]) {
  char buf[MAX_PACKET_LEN];

  rtable = malloc(sizeof(struct route_table_entry) * 100000);
  DIE(rtable == NULL, "memory");
  rtable_len = read_rtable(argv[1], rtable);
  qsort(rtable, rtable_len, sizeof(struct route_table_entry), comp);

  arp_table = malloc(100 * sizeof(struct arp_table_entry));
  arp_table_len = 0;

  queue q = queue_create();

  uint8_t mac[6] = {0};

  // Do not modify this line
  init(argc - 2, argv + 2);

  while (1) {
    int interface;
    size_t len;

    interface = recv_from_any_link(buf, &len);
    DIE(interface < 0, "recv_from_all_links");

    struct ether_header *eth_hdr = (struct ether_header *)buf;
    /* Note that packets received are in network order,
                any header field which has more than 1 byte will need to be
       conerted to host order. For example, ntohs(eth_hdr->ether_type). The
       oposite is needed when sending a packet on the link, */
    struct icmphdr *icmp_hdr =
        (struct icmphdr *)(buf + sizeof(struct ether_header) +
                           sizeof(struct iphdr));
    struct iphdr *ip_hdr =
        (struct iphdr *)((void *)eth_hdr + sizeof(struct ether_header));

    get_interface_mac(interface, mac);

    // Check if packet is IPv4
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
      uint16_t old_check = ntohs(ip_hdr->check);
      ip_hdr->check = 0;
      uint16_t new_check = checksum((void *)ip_hdr, sizeof(struct iphdr));
      if (old_check != new_check) {
        continue;
      }

      if (ip_hdr->ttl <= 1) {
        uint8_t mac[6];
        get_interface_mac(get_best_route(ip_hdr->saddr)->interface, mac);
        send_icmp_request(ip_hdr->saddr, mac, eth_hdr->ether_shost, 11, 0,
                          (const uint8_t *)(ip_hdr + 1),
                          ntohs(ip_hdr->tot_len) - sizeof(struct iphdr),
                          get_best_route(ip_hdr->saddr)->interface);
        continue;
      }

      if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) &&
          ip_hdr->protocol == 1) {
        if (icmp_hdr->type == 8) {
          send_icmp_request(ip_hdr->saddr, eth_hdr->ether_dhost,
                            eth_hdr->ether_shost, 0, 0,
                            (const uint8_t *)(icmp_hdr + 1),
                            len - sizeof(struct ether_header) -
                                sizeof(struct iphdr) - sizeof(struct icmphdr),
                            interface);
          continue;
        }
      }

      struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
      if (best_route == NULL) {
        uint8_t mac[6];
        get_interface_mac(get_best_route(ip_hdr->saddr)->interface, mac);
        send_icmp_request(ip_hdr->saddr, mac, eth_hdr->ether_shost, 3, 0,
                          (const uint8_t *)(ip_hdr + 1),
                          ntohs(ip_hdr->tot_len) - sizeof(struct iphdr),
                          get_best_route(ip_hdr->saddr)->interface);
        continue;
      }

      ip_hdr->ttl -= 1;
      ip_hdr->check = 0;
      ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

      u_int8_t *mac_router = malloc(6);
      get_interface_mac(best_route->interface, mac_router);

      struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);

      if (!arp_entry) {
        char buf_copy[MAX_PACKET_LEN];
        memcpy(buf_copy, &len, sizeof(size_t));
        memcpy(buf_copy + sizeof(size_t), buf, len);
        queue_enq(q, buf_copy);

        struct ether_header *eth_hdr_arp = malloc(sizeof(struct ether_header));
        eth_hdr_arp->ether_type = htons(ETHERTYPE_ARP);

        get_interface_mac(best_route->interface, eth_hdr_arp->ether_shost);
        for (int i = 0; i < 6; i++) {
          eth_hdr_arp->ether_dhost[i] = 0xff;
        }

        struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
        arp_hdr->htype = htons(1);
        arp_hdr->ptype = htons(ETHERTYPE_IP);
        arp_hdr->hlen = 6;
        arp_hdr->plen = 4;
        arp_hdr->op = htons(1);
        memcpy(arp_hdr->sha, eth_hdr_arp->ether_shost, 6);
        arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
        for (int i = 0; i < 6; i++) {
          arp_hdr->tha[i] = 0;
        }
        arp_hdr->tpa = best_route->next_hop;

        char *packet =
            malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
        memcpy(packet, eth_hdr_arp, sizeof(struct ether_header));
        memcpy(packet + sizeof(struct ether_header), arp_hdr,
               sizeof(struct arp_header));

        send_to_link(best_route->interface, packet,
                     sizeof(struct ether_header) + sizeof(struct arp_header));

        continue;
      } else {
        get_interface_mac(best_route->interface, eth_hdr->ether_shost);
        for (int i = 0; i < 6; i++) {
          if (arp_table[i].ip == best_route->next_hop) {
            memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
          }
        }

        send_to_link(best_route->interface, buf, len);
      }

    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
      struct arp_header *arp_hdr =
          (struct arp_header *)(buf + sizeof(struct ether_header));
      // Check if ARP request
      if (arp_hdr->op == htons(1)) {
        if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
          memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
          memcpy(eth_hdr->ether_shost, mac, 6);

          memcpy(arp_hdr->tha, arp_hdr->sha, 6);
          memcpy(arp_hdr->sha, mac, 6);

          u_int32_t aux = arp_hdr->tpa;
          arp_hdr->tpa = arp_hdr->spa;
          arp_hdr->spa = aux;
          arp_hdr->op = htons(2);

          send_to_link(interface, buf, len);
          continue;
        }
        // Check if ARP reply
      } else if (arp_hdr->op == htons(2)) {
        if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
          struct arp_table_entry *arp_entry =
              malloc(sizeof(struct arp_table_entry));

          memcpy(arp_entry->mac, arp_hdr->sha, 6);
          arp_entry->ip = arp_hdr->spa;
          arp_table[arp_table_len++] = *arp_entry;

          while (queue_empty(q) == 0) {
            char *packet = queue_deq(q);

            size_t packet_len;
            memcpy(&packet_len, packet, sizeof(size_t));
            char buf_copy[MAX_PACKET_LEN];
            memcpy(buf_copy, packet + sizeof(size_t), packet_len);

            struct iphdr *ip_hdr_copy =
                (struct iphdr *)(buf_copy + sizeof(struct ether_header));
            struct ether_header *eth_hdr_copy = (struct ether_header *)buf_copy;

            struct route_table_entry *best_route =
                get_best_route(ip_hdr_copy->daddr);

            struct arp_table_entry *arp_entry =
                get_arp_entry(best_route->next_hop);

            if (!arp_entry) {
              continue;
            } else {
              get_interface_mac(best_route->interface,
                                eth_hdr_copy->ether_shost);
              for (int i = 0; i < 6; i++) {
                if (arp_table[i].ip == best_route->next_hop) {
                  memcpy(eth_hdr_copy->ether_dhost, arp_table[i].mac, 6);
                }
              }

              send_to_link(best_route->interface, buf_copy, packet_len);
            }
          }
        }
      }
    }
  }

  free(rtable);
  free(arp_table);

  return 0;
}
