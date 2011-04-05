/**
 *  Functions for ARP table build and refresh, ARP getters and setters
 */
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
/*---------------------------------------------------------------------------*/
/**
 * Check age of ARP table, broadcast request if stale
 */
void
sr_arp_check_age (struct sr_instance *sr)
{
  time_t t, age, refreshage;
  int i;
  struct sr_arp_entry *entry;

  assert (sr);

  refreshage = time (&t) - sr->arp_last_reftime;


  if (refreshage >= ARP_CHECK_EVERY)
    {
      for (i = 0; i < ARP_MAX_ENTRIES; i++)
	{
	  entry = &sr->arp_table[i];
	  if (!entry->ip)
	    continue;

	  age = t - entry->created;
	  printf ("ARP: Entry %i is %lds old (ttl %ds)\n", i, age, ARP_TTL);
	  if (age <= ARP_TTL)
	    continue;

	  printf ("ARP: Updating ");
	  sr_arp_print_entry (i, *entry);

	  entry->tries++;
	  sr_arp_refresh (sr, entry->ip, entry->iface->name);
	}
      sr->arp_last_reftime = t;
    }
}

/*---------------------------------------------------------------------------*/
/** 
    arp setter 
    set an arp entry given IP and MAC address
*/
struct sr_arp_entry *
sr_arp_set (struct sr_instance *sr, uint32_t ip, unsigned char *mac,
	    struct sr_if *iface)
{
  struct sr_arp_entry *entry = sr_arp_get (sr, ip);
  struct in_addr n;

  assert (sr);
  assert (ip);
  assert (mac);
  assert (iface);

  memset (entry, 0, sizeof (struct sr_arp_entry));
  entry->ip = ip;
  if (mac)
    {
      memcpy (entry->mac, mac, ETHER_ADDR_LEN);
    }
  entry->iface = iface;
  entry->tries = 0;
  time (&entry->created);

  n.s_addr = entry->ip;
  printf ("ARP: Created entry %s\n", inet_ntoa (n));
  sr_arp_print_table (sr);

  return entry;
}

/*---------------------------------------------------------------------------*/
/**
    Get entries. Indices based on max. no. of ARP entries (ARP_MAX_ENTRIES)
*/
/*---------------------------------------------------------------------------*/
struct sr_arp_entry *
sr_arp_get (struct sr_instance *sr, uint32_t ip)
{
  int i;
  struct sr_arp_entry *entry;

  assert (sr);
  assert (ip);

  /* scan table for entries */
  for (i = 0; i < ARP_MAX_ENTRIES; i++)
    {
      entry = &sr->arp_table[i];
      if (entry->ip == ip || entry->ip == 0)
	return entry;
    }
  return NULL;
}

/*---------------------------------------------------------------------------*/
/**
    Refresh ARP table
*/
/*---------------------------------------------------------------------------*/
void
sr_arp_refresh (struct sr_instance *sr, uint32_t ip, char *interface)
{
  int i;
  struct sr_arp_entry *entry;
  uint8_t packet[sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr)];
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *) packet;
  struct sr_arphdr *a_hdr =
    (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));
  struct sr_if *iface = sr_find_interface (sr, interface);

  assert (sr);
  assert (ip);
  assert (interface);
  if (!iface)
    {
      printf ("ARP: sr_arp_refresh: interface %s not found: aborting\n",
	      interface);
      return;
    }

  /* ethernet header for broadcast */
  memset ((void *) packet, 0, sizeof (packet));
  for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
      e_hdr->ether_dhost[i] = 0xFF;
      e_hdr->ether_shost[i] = iface->addr[i];
    }
  e_hdr->ether_type = htons (ETHERTYPE_ARP);

  /* arp message for broadcast */
  a_hdr->ar_hrd = htons (ARPHDR_ETHER);
  a_hdr->ar_pro = htons (ETHERTYPE_IP);
  a_hdr->ar_hln = ETHER_ADDR_LEN;
  a_hdr->ar_pln = sizeof (uint32_t);
  a_hdr->ar_op = htons (ARP_REQUEST);
  memcpy (a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  a_hdr->ar_sip = iface->ip;
  memcpy (a_hdr->ar_tha, sr_arp_get (sr, ip), ETHER_ADDR_LEN);
  a_hdr->ar_tip = ip;

  /* make an arp entry */
  entry = sr_arp_get (sr, ip);
  
  /* send the packet on the interface */
  sr_send_packet (sr, packet, sizeof (packet), interface);
}

/*---------------------------------------------------------------------------*/
/**
 * convert an ARP request packet to ARP response
 */
/*---------------------------------------------------------------------------*/
void
sr_arp_convert_request_response (struct sr_instance *sr,
				 uint8_t * packet,
				 unsigned int len, struct sr_if *iface)
{
  struct sr_ethernet_hdr *e_hdr = 0;
  struct sr_arphdr *a_hdr = 0;
  uint32_t tmp_ip;

  assert (sr);
  assert (packet);
  assert (len);
  assert (iface->ip);

  e_hdr = (struct sr_ethernet_hdr *) packet;
  a_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

  /* Is this packet for us? */
  if (iface->ip != a_hdr->ar_tip)
    {
      printf ("ARP: Arp request is not for us!");
      return;
    }

  /* Convert to response */
  memcpy (e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy (e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  a_hdr->ar_op = htons (ARP_REPLY);

  /* Swap out broadcast address for our eth address */
  memcpy (a_hdr->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy (a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

  /* Swap out IPs */
  tmp_ip = a_hdr->ar_sip;
  a_hdr->ar_sip = a_hdr->ar_tip;
  a_hdr->ar_tip = tmp_ip;
  sr_send_packet (sr, (uint8_t *) packet, len, iface->name);
}

/*---------------------------------------------------------------------------*/
/**
    scan the ARP table (as per st_rt.c's sr_print_routing_table routine) and send ARP requests
*/
/*---------------------------------------------------------------------------*/
void
sr_arp_scan (struct sr_instance *sr)
{
  struct sr_rt *rt_walker = 0;

  assert (sr);
  if (sr->routing_table == 0)
    {
      printf ("ARP: Routing table empty \n");
      return;
    }

  rt_walker = sr->routing_table;

  sr_arp_refresh (sr, rt_walker->gw.s_addr, rt_walker->interface);
  while (rt_walker->next)
    {
      rt_walker = rt_walker->next;
      sr_arp_refresh (sr, rt_walker->gw.s_addr, rt_walker->interface);
    }

}

/*---------------------------------------------------------------------------*/
/** 
 *  print out the ARP table
 */
/*---------------------------------------------------------------------------*/
void
sr_arp_print_table (struct sr_instance *sr)
{
  int i;
  printf ("ARP: Current arp entries out of a total of %d:\n",
	  ARP_MAX_ENTRIES);
  for (i = 0; i < ARP_MAX_ENTRIES; i++)
    {
      if (sr->arp_table[i].ip)
	sr_arp_print_entry (i, sr->arp_table[i]);
    }
  printf ("ARP: End of arp table.\n");
}

/*---------------------------------------------------------------------------*/
/* Print out an ARP Entry 


*/
/*---------------------------------------------------------------------------*/
void
sr_arp_print_entry (int i, struct sr_arp_entry entry)
{
  time_t t, age;
  struct in_addr pr_ip;

  pr_ip.s_addr = entry.ip;
  age = time (&t) - entry.created;

  printf ("ARP: table entry %d ip %s mac ", i, inet_ntoa (pr_ip));
  DebugMAC (entry.mac);
  printf (" tries %d age %lds created %s ", entry.tries, age,
	  ctime (&entry.created));
}
