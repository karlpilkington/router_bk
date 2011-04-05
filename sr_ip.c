/**
 * Routines for handling IP packets
 */
#include <assert.h>
#include <string.h>
#include "sr_router.h"
#include "sr_rt.h"

/**
 * Swaps the ethernet address and ip when sending back packet on  
 * same interface
 */
void
sr_ip_reverse (struct sr_ip_comb *p, uint16_t len)
{
  uint8_t shost[ETHER_ADDR_LEN];
  uint32_t s_ip;

  assert (p);

  /* swap MAC addresses */
  memcpy (shost, p->eth.ether_dhost, ETHER_ADDR_LEN);
  memcpy (p->eth.ether_dhost, p->eth.ether_shost, ETHER_ADDR_LEN);
  memcpy (p->eth.ether_shost, shost, ETHER_ADDR_LEN);


  /* Set header length (At least 5) */
  if (p->ip.ip_hl != 5)
    {
      p->ip.ip_hl = 5;		/* set to 5 */


    }
  p->ip.ip_off = 0;
  p->ip.ip_ttl = HOP_LIMIT;
  p->ip.ip_p = IPPROTO_ICMP;
  p->ip.ip_sum = 0;

  /* swap IP addresses */
  s_ip = p->ip.ip_dst.s_addr;
  p->ip.ip_dst.s_addr = p->ip.ip_src.s_addr;
  p->ip.ip_src.s_addr = s_ip;

  /* recalculate length */
  p->ip.ip_len = htons (len);

  /* Recompute checksum */
  p->ip.ip_sum = sr_ip_checksum ((uint16_t *) & p->ip, (p->ip.ip_hl * 4));
  Debug ("IP: calculated ip checksum %X, recalculated %X \n",
	 ntohs (p->ip.ip_sum),
	 sr_ip_checksum ((uint16_t *) & p->ip, sizeof (struct ip)));
}

/**
 ICMP unreachable construction - Reference : http://www.networksorcery.com/enp/protocol/icmp/msg3.htm
 */
int
sr_icmp_unreachable (struct sr_bundle *h)
{
  uint8_t data[ICMP_TIMEOUT_SIZE];
  struct sr_rt *receiver;
  struct sr_ip_comb *p;

  assert (h);
  p = h->pkt;

  /* The IP header followed by 8 bytes of the original data from datagram */
  memcpy (data, (uint8_t *) & p->ip, ICMP_TIMEOUT_SIZE);
  receiver = sr_rt_locate(h->sr, p->ip.ip_dst.s_addr);
  p->ip.ip_dst.s_addr = h->sr->interfaces[ receiver->ifidx ]->ip;

  sr_ip_reverse (p, 60); //ip+icmp+data = 60

  /* create the icmp packet */
  p->d.icmp.type = ICMP_TIME_EXCEEDED;
  p->d.icmp.code = 0;


  /* Make the checksum zero */
  p->d.icmp.checksum = 0;

  /* clear data from unused field */
  p->d.icmp.fields.timeout.unused = 0;

  /* data from original */
  memcpy (p->d.icmp.data, data, ICMP_TIMEOUT_SIZE);

  p->d.icmp.checksum =
    sr_ip_checksum ((uint16_t *) & p->d.icmp, (ICMP_TIMEOUT_SIZE + 8));

  /* recalculate size of packet */
  h->len = sizeof (struct sr_ethernet_hdr) + ntohs (p->ip.ip_len);

  return 1;
}

/**
 * Handler for ICMP request
 * 
 */
int
sr_icmp_handler (struct sr_bundle *h)
{
  struct sr_ip_comb *p;
  struct ip *ip;
  uint8_t type;
  uint16_t len, hops;
  struct sr_if *iface;

  assert (h);
  p = h->pkt;
  type = p->d.icmp.type;
  ip = &h->pkt->ip;
  Debug("IP: Type of ICMP packet is %d\n", type);

  switch (type)
    {
    case ICMP_ECHO_REQUEST:
      Debug ("IP - ICMP - ECHO REQUEST\n");
      sr_ip_reverse (p, ntohs (ip->ip_len));
      p->d.icmp.type = 0;
      p->d.icmp.code = 0;
      p->d.icmp.checksum = 0;
      len = h->raw_len - sizeof (h->pkt->eth) - sizeof (h->pkt->ip);
      p->d.icmp.checksum = sr_ip_checksum ((uint16_t *) & p->d.icmp, len);
      return 1;

    case ICMP_TRACEROUTE:
      Debug ("IP: ICMP: TRACEROUTE REQUEST");
      sr_ip_reverse (p, ntohs (ip->ip_len));
      p->d.traceroute.checksum = 0;
      hops = ntohs (p->d.traceroute.in_hops) + 1;
      Debug ("HOPS %d\n", hops);
      p->d.traceroute.in_hops = htons (hops);
      p->d.traceroute.mtu = htonl (1500);
      iface = sr_if_get_iface_ip (h->sr, ip->ip_src.s_addr);
      p->d.traceroute.speed = htonl (iface->speed);
      len = h->raw_len - sizeof (h->pkt->eth) - sizeof (h->pkt->ip);
      p->d.icmp.checksum = sr_ip_checksum ((uint16_t *) & p->d.icmp, len);
      return 1;

    case ICMP_UNREACHABLE:
      Debug ("IP: ICMP UNREACHABLE");
    default:
      Debug ("IP: ICMP: ID %d\n", type);
      /* ICMP packet for an interface */
      if (sr_if_get_iface_ip (h->sr, ip->ip_dst.s_addr))
	return 0;
      Debug ("IP: icmp: forwarding packet\n");
      return sr_ip_forward (h);
    }
  return 0;
}

/**
 * Transparent for TCP and UDP packets, filters out if protocol is unknown
 */
int
sr_ip_handler (struct sr_bundle *h)
{
  switch (h->pkt->ip.ip_p)
    {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
      return sr_ip_forward (h);
    default:
      Debug ("IP: other : abort\n");
    }
  return 0;
}

/**
 * Decrement TTL and forward packet
 */
int
sr_ip_forward (struct sr_bundle *h)
{
  struct ip *ip;

  assert (h);

  ip = &h->pkt->ip;
  ip->ip_ttl -= 0x01;
  ip->ip_sum = 0;
  ip->ip_sum = sr_ip_checksum ((uint16_t *) ip, (ip->ip_hl * 4));
  Debug
    ("IP: ttl is %d, Recalculate ip checksum %X (checked value %X)\n",
     ip->ip_ttl, ntohs (h->pkt->ip.ip_sum), sr_ip_checksum ((uint16_t *) ip,
							    (ip->ip_hl * 4)));

  return 1;
}

/**
 * Checksum calculations
 *
 * Reference : http://www.faqs.org/rfcs/rfc1071.html 
 *  
 * 
 */
uint16_t
sr_ip_checksum (uint16_t const data[], uint16_t tot_len)
{
  uint32_t sum = 0;
  uint16_t words = tot_len / 2;

  /*add up 2 octet parts */
  while (words-- > 0)
    {
      sum += *(data++);
    }
  if (tot_len % 2)  /*handle odd case*/
    {
      	     
      sum += (*data << 8);
    }

  /* 1s complement */
  while (sum >> 16)
    {
      sum = (sum >> 16) + (sum & 0xFFFF);
    }

  /* invert */
  return ((uint16_t) ~ sum);
}
