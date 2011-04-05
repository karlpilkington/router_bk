/**
 * ARP header. Define data structures for ARP entries, and timeouts
 */
#ifndef SR_ARP_H
#define SR_ARP_H

#include <sys/time.h>
#include <stdint.h>
#include "sr_protocol.h"
#include "sr_if.h"

/** data structure for an arp entry */
struct sr_arp_entry
{
  uint32_t ip;
  unsigned char mac[ETHER_ADDR_LEN];
  struct sr_if *iface;
  uint8_t tries;
  time_t created;
};

/** Bitmask to get index from IP */
#define ARP_MASK 0xFF

/** Changes size of ARP table in interface */
#define ARP_MAX_ENTRIES (ARP_MASK+1)

/** TTL for a single ARP entry*/
#define ARP_TTL 60
/** time to wait between successive ARP checks */
#define ARP_CHECK_EVERY 10
/** Try these many times for ARP before giving up */
#define ARP_MAX_TRIES 5

#endif
