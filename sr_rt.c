/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002  
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*--------------------------------------------------------------------- 
 * locate routing entry for a given ip address
 * 
 *
 * returns address of  entry
 *---------------------------------------------------------------------*/
struct sr_rt *
sr_rt_locate (struct sr_instance *sr, uint32_t ip)
{
  struct sr_rt *search_inst, *elsewhere, *matchingpref;
  uint32_t prfx, longpref;

  assert (sr);
  assert (ip);

  search_inst = sr->routing_table;
  assert (search_inst);

  prfx = longpref = 0;
  //first entry test

  if (search_inst->dest.s_addr == 0)
    {
      elsewhere = search_inst;
    }
  else if ((prfx = (search_inst->dest.s_addr & search_inst->mask.s_addr)) ==
	   (ip & search_inst->mask.s_addr))
    {
      matchingpref = search_inst;
      longpref = prfx;
      if (search_inst->mask.s_addr == 0xFFFFFFFF)
	return search_inst;
    }
  //search remaining
  while (search_inst->next)
    {
      search_inst = search_inst->next;
      if (search_inst->dest.s_addr == 0)
	{
	  elsewhere = search_inst;
	}
      else if ((prfx =
		(search_inst->dest.s_addr & search_inst->mask.s_addr)) ==
	       (ip & search_inst->mask.s_addr))
	{
	  if (longpref == 0 || prfx > longpref)
	    {
	      longpref = prfx;
	      matchingpref = search_inst;
	      if (search_inst->mask.s_addr == 0xFFFFFFFF)
		return search_inst;
	    }
	}
    }
  if (longpref == 0)
    return elsewhere;
  return matchingpref;
}

/**
 * free routing table 
 */
void
sr_rt_clear (struct sr_instance *sr)
{
  struct sr_rt *r, *del;

  assert (sr);
  r = sr->routing_table;
  while (r)
    {
      del = r;
      r = r->next;
      free (del);
    }
  sr->routing_table = 0;
}

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

int
sr_load_rt (struct sr_instance *sr, const char *filename)
{
  FILE *fp;
  char line[BUFSIZ];
  char dest[32];
  char gw[32];
  char mask[32];
  char iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;

  /* -- REQUIRES -- */
  assert (filename);
  if (access (filename, R_OK) != 0)
    {
      perror ("access");
      return -1;
    }

  fp = fopen (filename, "r");

  while (fgets (line, BUFSIZ, fp) != 0)
    {
      sscanf (line, "%s %s %s %s", dest, gw, mask, iface);
      if (inet_aton (dest, &dest_addr) == 0)
	{
	  fprintf (stderr,
		   "Error loading routing table, cannot convert %s to valid IP\n",
		   dest);
	  return -1;
	}
      if (inet_aton (gw, &gw_addr) == 0)
	{
	  fprintf (stderr,
		   "Error loading routing table, cannot convert %s to valid IP\n",
		   gw);
	  return -1;
	}
      if (inet_aton (mask, &mask_addr) == 0)
	{
	  fprintf (stderr,
		   "Error loading routing table, cannot convert %s to valid IP\n",
		   mask);
	  return -1;
	}
      sr_add_rt_entry (sr, dest_addr, gw_addr, mask_addr, iface);
    }				/* -- while -- */

  return 0;			/* -- success -- */
}				/* -- sr_load_rt -- */

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

void
sr_add_rt_entry (struct sr_instance *sr, struct in_addr dest,
		 struct in_addr gw, struct in_addr mask, char *if_name)
{
  struct sr_rt *rt_search_inst = 0;

  /* -- REQUIRES -- */
  assert (if_name);
  assert (sr);

  /* -- empty list special case -- */
  if (sr->routing_table == 0)
    {
      sr->routing_table = (struct sr_rt *) malloc (sizeof (struct sr_rt));
      assert (sr->routing_table);
      sr->routing_table->next = 0;
      sr->routing_table->dest = dest;
      sr->routing_table->gw = gw;
      sr->routing_table->mask = mask;
      sr->routing_table->ifidx = sr_name_index (if_name);
      strncpy (sr->routing_table->interface, if_name, sr_IFACE_NAMELEN);
      return;
    }

  /* -- find the end of the list -- */
  rt_search_inst = sr->routing_table;
  while (rt_search_inst->next)
    {
      rt_search_inst = rt_search_inst->next;
    }

  rt_search_inst->next = (struct sr_rt *) malloc (sizeof (struct sr_rt));
  assert (rt_search_inst->next);
  rt_search_inst = rt_search_inst->next;

  rt_search_inst->next = 0;
  rt_search_inst->dest = dest;
  rt_search_inst->gw = gw;
  rt_search_inst->mask = mask;
  strncpy (rt_search_inst->interface, if_name, sr_IFACE_NAMELEN);

}				/* -- sr_add_entry -- */

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

void
sr_print_routing_table (struct sr_instance *sr)
{
  struct sr_rt *rt_walker = 0;

  if (sr->routing_table == 0)
    {
      printf (" Routing table empty \n");
      return;
    }

  printf ("Destination\tGateway\t\tMask\tIface\n");

  rt_walker = sr->routing_table;

  sr_print_routing_entry (rt_walker);
  while (rt_walker->next)
    {
      rt_walker = rt_walker->next;
      sr_print_routing_entry (rt_walker);
    }

}				/* -- sr_print_routing_table -- */

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

void
sr_print_routing_entry (struct sr_rt *entry)
{
  /* -- REQUIRES -- */
  assert (entry);
  assert (entry->interface);

  printf ("%s\t\t", inet_ntoa (entry->dest));
  printf ("%s\t", inet_ntoa (entry->gw));
  printf ("%s\t", inet_ntoa (entry->mask));
  printf ("%s\n", entry->interface);

}				/* -- sr_print_routing_entry -- */
