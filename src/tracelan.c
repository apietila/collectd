/**
 * collectd - src/tracelan.c
 * Copyright (C) 2015       Anna-Kaisa Pietilainen
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Anna-Kaisa Pietilainen <annakaisa.pietilainen at gmail.com>
 **/

#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"

#include <pthread.h>
#include <poll.h>
#include <math.h>
#include <inttypes.h>

// libtrace
#include <libtrace.h>

// from libtcptools
#include <sessionmanager.h>
#include <rttnsequence.h>

// See: http://www.wikiwand.com/en/Standard_deviation#/Rapid_calculation_methods
#define _stddev(cnt, sum, ssq) sqrt(((double)(cnt)*ssq - sum*sum)/((double)(cnt*(cnt - 1))))

#define TRACE_SNAPLEN 100
#define TRACE_OUTGOING 0
#define TRACE_INCOMING 1

/*
 * Private variables
 */
static const char *config_keys[] =
{
  "Interface"
};
static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

// TODO: could support multiple (lan) interfaces, now assume we
// capture on the br-lan (or equivalent) to get all LAN traffic 
static char *interface = NULL;

static pthread_t       listen_thread;
static int             listen_thread_init = 0;
static pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct tracelan_report {
  uint8_t used;
  uint8_t mac[6];
  uint64_t count_in;
  uint64_t bytes_in;
  uint64_t count_out;
  uint64_t bytes_out;
  uint64_t samples;  // number of RTT samples
  double sum;        // running RTT sample sum
  double ssq;        // running RTT sample sum of squares
  double min;        // smallest RTT sample seen on report period
  double max;        // largest RTT sample seen on report period
  double mean;       // report period RTT mean
  double std;        // report period RTT std dev
} tracelan_report_t;

// report per client (TODO: max num of clients, or use hashtable ?)
static tracelan_report_t reports[32];
static int report_len = 32;

static uint64_t packets_dropped = 0;
static uint64_t packets_dropped_prev = 0;

/* Clear out the reports. */
static void tracelan_reset_report() {
  int i;
  for (i = 0; i < report_len; i++) {  
    reports[i].count_in = 0;
    reports[i].bytes_in = 0;
    reports[i].count_out = 0;
    reports[i].bytes_out = 0;
    reports[i].samples = 0;
    reports[i].min = -1.0;
    reports[i].max = -1.0;
    reports[i].sum = 0;
    reports[i].ssq = 0;
    reports[i].mean = 0;
    reports[i].std = 0;    
    reports[i].used = 0;
  }
}

/* Calculate stats. */
static void tracelan_finalize_report() {
  int i;
  for (i = 0; i < report_len; i++) {  
    if (reports[i].used && reports[i].samples > 1) {
      reports[i].mean = reports[i].sum/(reports[i].samples);
      reports[i].std = _stddev((reports[i].samples), 
			       reports[i].sum, 
			       reports[i].ssq);
      if (reports[i].min < 0)
	reports[i].min = 0.0;
      if (reports[i].max < 0)
	reports[i].max = 0.0;
    }
  }
}
 
/* Handle packet. */
static void tracelan_packet_callback(libtrace_packet_t *packet, tcp_session_t *session) {
  double rtt;
  int dir, i;   
  uint8_t *mac;
  uint64_t h;
  tracelan_report_t r;

  dir = trace_get_direction(packet);
  if (!(dir == TRACE_OUTGOING || dir == TRACE_INCOMING)) {
    return; // unknown direction
  }

  // the LAN client mac
  if (dir == TRACE_OUTGOING)
    mac = trace_get_destination_mac(packet);
  else
    mac = trace_get_source_mac(packet);

  // report table index
  h = 0;
  for (i=0; i<6; i++) 
    h = (h<<8) + mac[i];
  h = h%report_len;

  pthread_mutex_lock(&report_mutex);

  // FIXME: collisions!!
  r = reports[h];
  if (!r.used) {
    for (i=0; i<6; i++) 
      r.mac[i] = mac[i];
    r.used = 1;
  }

  if (dir == TRACE_OUTGOING) {
    // going towards the node
    r.count_out++;
    r.bytes_out += trace_get_wire_length(packet);
  } else {
    // coming in from the node
    r.count_in++;
    r.bytes_in += trace_get_wire_length(packet);
    
    if (session != NULL) {
      // RTT to the node (from outgoing DATA + incoming ACK)
      rtt = rtt_n_sequence_last_sample(session->data[0]);
      if (rtt > 0) {
	rtt = rtt * 1000.0; // in ms
	r.samples += 1;
	r.sum += rtt;
	r.ssq += (rtt*rtt);
	if (r.min < 0 || rtt < r.min)
	  r.min = rtt;
	if (r.max < 0 || rtt > r.max)
	  r.max = rtt;
      }
    }
  }

  pthread_mutex_unlock(&report_mutex);

  return;
}

/* Main capture thread loop. */
static int tracelan_run_loop(void) {
  libtrace_err_t err;
  libtrace_t *trace;
  libtrace_packet_t *packet;
  session_manager_t *sm;
  int snaplen = TRACE_SNAPLEN;

  /* Don't block any signals */
  {
    sigset_t sigmask;
    sigemptyset (&sigmask);
    pthread_sigmask (SIG_SETMASK, &sigmask, NULL);
  }

  DEBUG("tracelan plugin: Opening trace `%s' ..", 
	((interface != NULL) ? interface : "not set"));

  trace = trace_create(interface);

  if (trace_is_err(trace)) {
    err = trace_get_err(trace);
    ERROR("tracelan plugin: Opening trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
    return (err.err_num);
  }

  if (trace_config(trace,TRACE_OPTION_SNAPLEN,&snaplen)) {
    ERROR("tracelan plugin: Setting snaplen for `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
  }

  if (trace_start(trace)) {
    err = trace_get_err(trace);
    ERROR("tracelan plugin: Starting trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
    trace_destroy(trace);
    return (err.err_num);
  }

  // create tcp session manager
  sm = session_manager_create();

  // create and register the data-ack based RTT module
  session_manager_register_module(sm,rtt_n_sequence_module()); 

  packet = trace_create_packet();

  while (trace_read_packet(trace, packet)>0) {
    tracelan_packet_callback(packet,session_manager_update(sm,packet));

    // FIXME: avoid doing this / packet ?
    pthread_mutex_lock(&stat_mutex);
    packets_dropped = trace_get_dropped_packets(trace);
    pthread_mutex_unlock(&stat_mutex);
  }

  trace_destroy_packet(packet);
    
  if (trace_is_err(trace)) {
    err = trace_get_err(trace);
    ERROR("tracelan plugin: Reading trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
  }

  trace_destroy(trace);
  session_manager_destroy(sm);

  return (0);
}

static int tracelan_sleep_one_interval(void) {
  cdtime_t interval;
  struct timespec ts = { 0, 0 };
  int status = 0;

  interval = plugin_get_interval();
  CDTIME_T_TO_TIMESPEC (interval, &ts);

  while (42) {
    struct timespec rem = { 0, 0 };

    status = nanosleep (&ts, &rem);
    if (status == 0)
      break;
    else if ((errno == EINTR) || (errno == EAGAIN)) {
	ts = rem;
	continue;
    } else
      break;
  }
  return (status);
}

static void *tracelan_child_loop(__attribute__((unused)) void *dummy) {
  int status = 0;
  while (42) {
    status = tracelan_run_loop();
    if (status != TRACE_ERR_INIT_FAILED)
      break;
    tracelan_sleep_one_interval();
  }
  listen_thread_init = 0;
  return (NULL);
}

// trace_[packets|octets] in/out per client
static void submit_derive(const char *client, 
			  const char *type, 
			  derive_t out, 
			  derive_t in) {
  value_t values[2];
  value_list_t vl = VALUE_LIST_INIT;
  
  values[0].derive = out;
  values[1].derive = in;
  
  vl.values = values;
  vl.values_len = 2;
  sstrncpy(vl.host, hostname_g, sizeof (vl.host));
  if (client)
    sstrncpy (vl.plugin_instance, client, sizeof (vl.plugin_instance));
  sstrncpy(vl.plugin, "tracelan", sizeof (vl.plugin));
  sstrncpy(vl.type, type, sizeof (vl.type));
  
  plugin_dispatch_values (&vl);
}

// trace_stats <dropped|received> (no client)
// trace_rtt <min|max|mean|std> per client
static void submit_gauge_value(const char *client, 
			       const char *type, 
			       const char *type_instance, 
			       gauge_t value) {
  value_t values[1];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = value;
  
  vl.values = values;
  vl.values_len = 1;
  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "tracelan", sizeof (vl.plugin));
  if (client != NULL)
    sstrncpy (vl.plugin_instance, client, sizeof (vl.plugin_instance));
  sstrncpy (vl.type, type, sizeof (vl.type));
  sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
  
  plugin_dispatch_values (&vl);
}

static int tracelan_config(const char *key, const char *value) {
  if (strcasecmp(key, "Interface") == 0) {
    if (interface != NULL)
      free(interface);

    if ((interface = strdup(value)) == NULL)
      return (1);
  }
  return (0);
}

static int tracelan_init(void) {
  int status;

  pthread_mutex_lock(&report_mutex);
  tracelan_reset_report();
  pthread_mutex_unlock(&report_mutex);

  if (listen_thread_init != 0)
    return (-1);

  status = plugin_thread_create(&listen_thread, 
				NULL, 
				tracelan_child_loop,
				(void *) 0);

  if (status != 0) {
    char errbuf[1024];
    ERROR("tracelan plugin: pthread_create failed: %s",
	  sstrerror(errno, errbuf, sizeof (errbuf)));
    return (-1);
  }

  listen_thread_init = 1;
  return (0);
}

static int tracelan_read(void) {
  int i,j;
  uint64_t drop;
  tracelan_report_t tmp[report_len];
  char mac[18];

  pthread_mutex_lock(&stat_mutex);

  // report stats per period
  if (packets_dropped != UINT64_MAX) {
    drop = packets_dropped - packets_dropped_prev;
    if (drop < 0) { // overflow
      drop = abs(drop) + packets_dropped;
    }
    packets_dropped_prev = packets_dropped;
  } else {
    drop = UINT64_MAX;
  }

  pthread_mutex_unlock(&stat_mutex);

  pthread_mutex_lock(&report_mutex);

  tracelan_finalize_report();
  for (i = 0; i < report_len; i++) {  
    if (reports[i].used) {
      tmp[i] = reports[i];
      for (j = 0; j < 6; j++)
	tmp[i].mac[j] = reports[i].mac[j];
    } else {
      tmp[i].used = 0;
    }
  }
  tracelan_reset_report();

  pthread_mutex_unlock(&report_mutex);

  // submit values per client
  for (i = 0; i < report_len; i++) {  
    tracelan_report_t r = tmp[i];
    if (r.used && (r.count_in + r.count_out) > 0) {
      unsigned char *addr = (unsigned char *)r.mac;
      snprintf(mac, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
	       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

      // traffic
      submit_derive(mac, "trace_packets", 
		    r.count_in, r.count_out); 
      submit_derive(mac, "trace_octets",
		    r.bytes_in, r.bytes_out); 

      // RTT stats
      if (r.samples>0) {
	submit_gauge_value(mac, "trace_rtt", "samples", r.samples);  
	submit_gauge_value(mac, "trace_rtt", "min", r.min);  
	submit_gauge_value(mac, "trace_rtt", "max", r.max);  
	submit_gauge_value(mac, "trace_rtt", "mean", r.mean);  
	submit_gauge_value(mac, "trace_rtt", "std", r.std);  
      }
    }
  }

  if (drop != UINT64_MAX)
    submit_gauge_value(NULL, "trace_stats", "dropped", drop);

  return (0);
}

void module_register (void) {
  plugin_register_config("tracelan", 
			 tracelan_config, 
			 config_keys, 
			 config_keys_num);
  plugin_register_init ("tracelan", tracelan_init);
  plugin_register_read ("tracelan", tracelan_read);
}
