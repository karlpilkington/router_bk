/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_buf.h"
#include "sr_arp_table.h"
#include "sr_ip.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */
struct sr_instance
{
  int sockfd;			/* socket to server */
  char user[32];		/* user name */
  char host[32];		/* host name */
  char template[30];		/* template name if any */
  char auth_key_fn[64];		/* auth key filename */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;	/* address to server */
  struct sr_if *if_list;	/* list of interfaces */
  struct sr_if *interfaces[ARP_MAX_ENTRIES];	/** interfaces ordered by name */

  struct sr_if *ip_iface_m[ARP_MAX_ENTRIES];   /** interfaces mapped to IPs */
  struct sr_rt *routing_table;	/* routing table */

  struct sr_buf buffer;   /** buffer for unsent packets */
  time_t arp_last_reftime;   /** last time we ran sr_arp_check_refresh in sr_arp.c */

  struct sr_arp_entry arp_table[ARP_MAX_ENTRIES];   /** ARP table for LAN*/

  char subnet_s[32];	/** subnet in string form*/
  uint32_t subnet;    /** subnet : numerical */
  uint32_t mask;   /** subnet mask */
  FILE *logfile;
};

/* -- sr_arp.c -- */
struct sr_arp_entry *sr_arp_set (struct sr_instance *sr, uint32_t ip,
				 unsigned char *mac, struct sr_if *iface);
struct sr_arp_entry *sr_arp_get (struct sr_instance *sr, uint32_t ip);

void sr_arp_scan (struct sr_instance *sr);
void sr_arp_check_age (struct sr_instance *sr);
void sr_arp_refresh (struct sr_instance *sr, uint32_t ip, char *interface);
void sr_arp_convert_request_response (struct sr_instance *sr,
				      uint8_t * packet, unsigned int len,
				      struct sr_if *iface);

void sr_arp_print_table (struct sr_instance *sr);
void sr_arp_print_entry (int i, struct sr_arp_entry entry);

/* -- sr_buf.c -- */
void sr_buf_clear (struct sr_instance *);
void sr_buf_add (struct sr_bundle *);
void sr_buf_remove (struct sr_instance *, struct sr_buf_entry *);

/* -- sr_ip.c -- */
int sr_icmp_handler (struct sr_bundle *);
int sr_icmp_unreachable (struct sr_bundle *);
int sr_ip_handler (struct sr_bundle *);
int sr_ip_forward (struct sr_bundle *);
uint16_t sr_ip_checksum (uint16_t const data[], uint16_t tot_len);

/* -- sr_main.c -- */
int sr_verify_routing_table (struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet (struct sr_instance *, uint8_t *, unsigned int,
		    const char *);
int sr_connect_to_server (struct sr_instance *, unsigned short, char *);
int sr_read_from_server (struct sr_instance *);
void sr_log_packet (struct sr_instance *sr, uint8_t * buf, int len);

/* -- sr_router.c -- */
void sr_init (struct sr_instance *);
void sr_handlepacket (struct sr_instance *, uint8_t *, unsigned int, char *);
int sr_router_send (struct sr_bundle *);
void sr_clear_backlog (struct sr_instance *);

/* -- sr_if.c -- */

uint8_t sr_name_index (const char *name);
struct sr_if *sr_find_interface (struct sr_instance *sr, const char *name);
struct sr_if *sr_if_get_iface_ip (struct sr_instance *sr, uint32_t ip);
void sr_if_clear (struct sr_instance *sr);

void sr_add_interface (struct sr_instance *, const char *);
void sr_set_ether_ip (struct sr_instance *, uint32_t);
void sr_set_ether_addr (struct sr_instance *, const unsigned char *);
void sr_print_if_list (struct sr_instance *);

#endif /* SR_ROUTER_H */
