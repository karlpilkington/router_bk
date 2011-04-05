#ifndef SR_IP_H
#define SR_IP_H
#include "sr_buf.h"
/** icmp types - reference:http://comp519.cs.rice.edu/images/e/eb/Icmp.pdf*/ 
#define ICMP_ECHO_REPLY 0x00
#define ICMP_UNREACHABLE 0x03
#define ICMP_PORT_UNAVAILABLE 0x03
#define ICMP_ECHO_REQUEST 0x08
#define ICMP_TIME_EXCEEDED 0x0b
#define ICMP_TRACEROUTE 0x1e
#define HOP_LIMIT 128

/** size in bytes of time exceeded data payload */
#define ICMP_TIMEOUT_SIZE 32

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 0x0001
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 0x0006
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 0x0011
#endif

#define IPDATASIZE (QSIZE-sizeof(struct sr_ethernet_hdr)-sizeof(struct ip))



/** Independent ICMP structs */
struct sr_icmp_timeout
{
  uint32_t unused;
} __attribute__ ((packed));

struct sr_icmp_unreachable
{
  uint16_t unused;
  uint16_t mtu;
} __attribute__ ((packed));

struct sr_icmp_echo_reply
{
  uint16_t id;
  uint16_t sequence;
} __attribute__ ((packed));

/** ICMP struct union */
union sr_icmp_fields
{
  struct sr_icmp_timeout timeout;
  struct sr_icmp_unreachable nothere;
  struct sr_icmp_echo_reply ping;
} __attribute__ ((packed));

struct sr_icmp
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  union sr_icmp_fields fields;
  uint8_t data[IPDATASIZE - 8];
} __attribute__ ((packed));

/** ICMP traceroute struct
    http://www.networksorcery.com/enp/protocol/icmp/msg30.htm */
struct sr_icmp_traceroute
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t unused;
  uint16_t out_hops;
  uint16_t in_hops;
  uint32_t speed;
  uint32_t mtu;
  uint8_t data[IPDATASIZE - 20];
} __attribute__ ((packed));
/** end icmp stuff */

/** udp and tcp base headers */
struct sr_tcp /** 20 bytes */
{
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack;
  uint16_t flags;		/* data offset:4, reserved:4, ecn:3, control bits:5 */
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
  uint8_t data[IPDATASIZE - 20];
} __attribute ((packed));

struct sr_udp /** 8 bytes */
{
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t len;
  uint16_t checksum;
  uint8_t data[IPDATASIZE - 8];
} __attribute__ ((packed));
/** end udp and tcp */

/** unified IP structs packed*/
union sr_ip_st_unif
{
  struct sr_tcp tcp;
  struct sr_udp udp;
  struct sr_icmp icmp;
  struct sr_icmp_traceroute traceroute;
} __attribute ((packed));

/** combined IP packet to pass */
struct sr_ip_comb
{
  struct sr_ethernet_hdr eth;
  struct ip ip;
  union sr_ip_st_unif d;
} __attribute ((packed));


#endif
