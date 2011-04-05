/**
 * defines data structures used by buffer and bundle passed to other functions
 */

#ifndef SR_BUF_H
#define SR_BUF_H

#define QSIZE 11000
#define QPADDING 16

/** Time before buffered packets become stale*/
#define STALE_TIMEOUT 6

/** Buffer size */
#define BUFFSIZE 256

/**
 * bundled data structure to pass into the sr_ip.c functions
 */
struct sr_bundle
{
  struct sr_instance *sr;
  uint8_t *raw;
  unsigned int raw_len;
  struct sr_ip_comb *pkt;
  unsigned int len;
  struct sr_if *iface;
  uint8_t buffered;
};

struct sr_buf_entry
{
  struct sr_bundle h;
  time_t created;
  struct sr_buf_entry *prev;
  struct sr_buf_entry *next;
  int pos;
};

struct sr_buf
{
  struct sr_buf_entry items[BUFFSIZE];
  uint8_t packets[BUFFSIZE][QSIZE];
  struct sr_buf_entry *start;
  struct sr_buf_entry *end;
};

#endif
