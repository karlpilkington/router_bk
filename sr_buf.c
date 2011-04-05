/**
 * Buffer routines
 */
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sr_router.h"
#include "sr_buf.h"
/**
 * Memory allocation for buffer 
 */

struct sr_buf_entry *
sr_buf_malloc (struct sr_instance *sr)
{
  struct sr_buf_entry *b;
  int i;

  assert (sr);

  for (i = 0; i < BUFFSIZE; i++)
    {
      b = &sr->buffer.items[i];
      if (b->h.buffered == 0)
	{
	  b->h.raw = sr->buffer.packets[i];
	  b->h.buffered = 1;
	  b->pos = i;
	  return b;
	}
    }
  return NULL;
}


/* free buffer*/
void
sr_buf_free (struct sr_instance *sr, struct sr_buf_entry *item)
{
  assert (sr);
  memset (&sr->buffer.packets[item->pos], 0, QSIZE + QPADDING);

  item->h.buffered = 0;
  item->h.pkt = 0;
  item->h.raw = 0;
  item->pos = -1;
  item->next = 0;
  item->prev = 0;
}

/**
 * Clear buffer (init and exit)
 */
void
sr_buf_clear (struct sr_instance *sr)
{
  int i;
  assert (sr);
  memset (&sr->buffer, 0, sizeof (struct sr_buf));
  sr->buffer.start = sr->buffer.end = 0;
  for (i = 0; i < BUFFSIZE; i++)
    {
      sr->buffer.items[i].pos = -1;
    }
}

/** 
 * save a packet to the buffer 
 */
void
sr_buf_add (struct sr_bundle *h)
{
  struct sr_instance *sr;
  struct sr_buf *b;
  struct sr_buf_entry *i;
  uint8_t *raw;
  struct ip *ip;

  assert (h);
  if (h->buffered)
    {
      Debug ("packet already buffered\n");
      return;
    }

  sr = h->sr;
  assert (sr);
  b = &sr->buffer;

  i = sr_buf_malloc (sr);
  raw = i->h.raw;
  if (!i)
    {
      Debug ("Buffer is out of memory\n");
      return;
    }
  h->buffered = 1;
  i->h = *h;
  i->h.raw = raw;
  memcpy (i->h.raw, h->raw, h->raw_len);
  i->h.pkt = (struct sr_ip_comb *) i->h.raw;
  time (&i->created);
  i->next = 0;

  ip = &i->h.pkt->ip;

  /* If this is the only item */
  if (!b->start)
    {
      b->start = i;
      i->prev = 0;

      /* if there are more buffered packets */
    }
  else
    {
      b->end->next = i;
      i->prev = b->end;
    }
  /* extend buffer */
  b->end = i;
}

/** 
 * remove a buffer item from buffer
 */
void
sr_buf_remove (struct sr_instance *sr, struct sr_buf_entry *item)
{
  struct sr_buf_entry *prev, *next, *delitem;
  struct sr_buf *b;

  assert (sr);
  b = &sr->buffer;

  if (item)
    {
      delitem = item;
      /* if this is not the only item in the list */
      if (item->next || item->prev)
	{
	  if (b->end == item)
	    b->end = item->prev;
	  if (b->start == item)
	    b->start = item->next;
	  prev = item->prev;
	  next = item->next;
	  if (next)
	    next->prev = prev;
	  if (prev)
	    prev->next = next;

	  /* if this is the only item in list */
	}
      else
	{
	  b->end = b->start = 0;
	}
      sr_buf_free (sr, delitem);
    }
}
