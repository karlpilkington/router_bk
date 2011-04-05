/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>


#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_buf.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void
sr_init (struct sr_instance *sr)
{
  /* REQUIRES */
  assert (sr);

}				/* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void
sr_handlepacket (struct sr_instance *sr, uint8_t * packet,
		 unsigned int len, char *interface)
{

  struct sr_if *iface = sr_find_interface (sr, interface);	
  	
  struct sr_ethernet_hdr *e_hdr = 0;
  struct sr_arphdr *a_hdr = 0;
  struct ip *ip = 0;
  struct sr_bundle ip_handler;

  struct sr_if *ip_match;	
  uint16_t checksum;
  int send_success;
  time_t t;

  /* REQUIRES */
  assert (sr);
  assert (packet);
  assert (interface);

  e_hdr = (struct sr_ethernet_hdr *) packet;

  time (&t);
  Debug ("ROUTER: %s", ctime (&t));


  ip = (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
  switch (ntohs (e_hdr->ether_type))
    {
    case ETHERTYPE_IP:
      Debug (" Received IP packet ");
      Debug ("src %s ", inet_ntoa (ip->ip_src));
      Debug ("dst %s ", inet_ntoa (ip->ip_dst));
      Debug ("(src %lX dst %lX subnet %lX)",
	     (unsigned long int) ip->ip_src.s_addr,
	     (unsigned long int) ip->ip_dst.s_addr,
	     (unsigned long int) sr->subnet);
      Debug ("\n");
      
      if (!((ip->ip_dst.s_addr & sr->subnet & sr->mask) == sr->subnet ||
	    (ip->ip_src.s_addr & sr->subnet & sr->mask) == sr->subnet))
	{
	  Debug ("Router: not for our subnet\n");
	  return;
	}
      else
	{
	  Debug ("ROUTER: packet for this subnet : processing\n");
	}
      if ((checksum = sr_ip_checksum ((uint16_t *) ip, (ip->ip_hl * 4))))
	{
	  Debug ("ROUTER: IP checksum failed (got %X) - abor\n",
		 checksum);
	  return;
	}

      memset (&ip_handler, 0, sizeof (struct sr_bundle));
      ip_handler.sr = sr;
      ip_handler.pkt = (struct sr_ip_comb *) packet;
      ip_handler.raw = packet;
      ip_handler.raw_len = len;
      ip_handler.len = len;
      ip_handler.iface = iface;

      /*TTL expiry case*/
      if (ip->ip_ttl <= 1)
	{
	  Debug ("TTL Expired - send unreachable\n");
	  if (!sr_icmp_unreachable (&ip_handler))
	    return;

	}
      else if (ip->ip_p == IPPROTO_ICMP)
	{
	  Debug ("ICMP protocol\n");
	  if (!sr_icmp_handler (&ip_handler))
	    return;

	}
      else if ((ip_match = sr_if_get_iface_ip (sr, ip->ip_dst.s_addr)))
	{
	  if (!sr_icmp_unreachable (&ip_handler))
            Debug ("IP packet for interface %s\n", ip_match->name);
	    return;

	}
      else
	{
	  Debug ("Packet : NON-ICMP IP packet %d\n", ip->ip_p);
	  if (!sr_ip_handler (&ip_handler))
	    return;
	}

      /* handle backlog */
      sr_clear_backlog (sr);
      /* then try and send packet */
      send_success = sr_router_send (&ip_handler);
      Debug ("Packet successfully sent %d\n", send_success);

      break;
    case ETHERTYPE_ARP:
      a_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));
      switch (ntohs (a_hdr->ar_op))
	{
	case ARP_REQUEST:
	  Debug ("ARP request - sending ARP reply\n");
	  sr_arp_convert_request_response (sr, packet, len, iface);
	  break;
	case ARP_REPLY:
	  Debug ("ARP reply - update ARP table\n");
	  sr_arp_set (sr, a_hdr->ar_sip, a_hdr->ar_sha, iface);
	  /* handle any backlog */
	  sr_clear_backlog (sr);
	  break;
	default:
	  Debug ("Unknown ARP value %d is!\n", a_hdr->ar_op);
	}
      break;
    default:
      Debug ("Error packet type %d\n",
	     e_hdr->ether_type);
    }

}				/* end sr_handlepacket */

/**--------------------------------------------------------------------- 
 * Method: sr_router_send
 * Send packets, buffer them if they cannot be sent
 * 
 *---------------------------------------------------------------------*/
int
sr_router_send (struct sr_bundle *h)
{
  struct sr_arp_entry *arp_entry;
  struct sr_rt *sender;
  struct sr_ethernet_hdr *eth;

  assert (h->sr);
  assert (h->pkt->ip.ip_dst.s_addr);

  sender = sr_rt_locate (h->sr, h->pkt->ip.ip_dst.s_addr);
  arp_entry = sr_arp_get (h->sr, sender->gw.s_addr);

  if (!arp_entry->ip)
    {
      Debug
	("Buffering packet\n");
      sr_buf_add (h);
      sr_arp_refresh (h->sr, sender->gw.s_addr, sender->interface);
      return 0;

    }
  else if (arp_entry->tries >= ARP_MAX_TRIES)
    {
      Debug
	("Router: out of tries");
      /* reconfigure message to indicate host is unreachable */
      if (!sr_icmp_unreachable (h))
	return 1;		/* Return error */
      sender = sr_rt_locate (h->sr, h->pkt->ip.ip_dst.s_addr);
      arp_entry = sr_arp_get (h->sr, sender->gw.s_addr);
      if (arp_entry->tries >= ARP_MAX_TRIES)
	{
	  Debug
	    ("Aborting ARP request");
	  return 1;		/* Return error status */
	}

    }
  else if (arp_entry->tries > 0)
    {
      Debug
	("Interface %s arp entry being refreshed (tries %d) - packet buffered\n",
	 sender->interface, arp_entry->tries);
      sr_buf_add (h);
      return 0;

    }
  Debug
    ("Sending packet of length %d bytes on interface %s\n",
     h->len, sender->interface);

  /* set mac addresses for tx */
  eth = &h->pkt->eth;
  memcpy (eth->ether_shost, arp_entry->iface->addr, ETHER_ADDR_LEN);
  memcpy (eth->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
  Debug ("ROUTER: Source IP %s (send mac ", inet_ntoa (h->pkt->ip.ip_src));
  DebugMAC (eth->ether_shost);
  Debug (") Destination IP %s (recv mac ", inet_ntoa (h->pkt->ip.ip_dst));
  DebugMAC (eth->ether_dhost);
  Debug (")\n");
  if (sr_send_packet (h->sr, h->raw, h->len, sender->interface) == -1)
    {
      Debug ("ROUTER: error sending packet - dropping\n");	/* - buffering\n"); */
      /* sr_buf_add(h);
         return 0; */
    }
  return 1;
}

/**
 * Handle backlogged packets, delete stale packets
 * 
 */
void
sr_clear_backlog (struct sr_instance *sr)
{
  struct sr_buf *b;
  struct sr_buf_entry *item, *next;
  struct ip *ip;
  time_t t;

  assert (sr);
  b = &sr->buffer;

  if (b->start)
    {
      item = b->start;
      while (item)
	{
	  ip = &item->h.pkt->ip;
	  next = item->next;
	  Debug ("ROUTER: attempting to resend packet (proto %d, from %s, ",
		 ip->ip_p, inet_ntoa (ip->ip_src));
	  Debug ("to %s)\n", inet_ntoa (ip->ip_dst));
	  if (time (&t) - item->created > STALE_TIMEOUT)
	    {
	      Debug ("ROUTER: packet too old - deleting\n");
	      sr_buf_remove (sr, item);
	    }
	  else if (sr_router_send (&item->h))
	    {
	      Debug ("ROUTER: packet successfully sent - deleting\n");
	      sr_buf_remove (sr, item);
	    }
	  item = next;
	}
    }
}
