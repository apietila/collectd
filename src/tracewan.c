/**
 * collectd - src/tracewan.c
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
#include <time.h>
#include <inttypes.h>

// libtrace
#include <libtrace.h>

// See: http://www.wikiwand.com/en/Standard_deviation#/Rapid_calculation_methods
#define _stddev(cnt, sum, ssq) sqrt(((double)(cnt)*ssq - sum*sum)/((double)(cnt*(cnt - 1))))

#define TRACE_SNAPLEN 50
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

static char *interface = NULL;

static pthread_t       listen_thread;
static int             listen_thread_init = 0;
static pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct tracewan_report {
  uint64_t count;  // packets
  uint64_t bytes;  // bytes 
  double sum;      // running sum of inter-arrivals
  double ssq;      // running sum of squares
  double min;      // smallest inter-arrival in report period
  double max;      // largest inter-arrival in report period
  double mean;     // report period inter-arrival mean
  double std;      // report period inter-arrival std dev
  double cv;       // report period inter-arrival cv (std/mean)
} tracewan_report_t;

// report per direction (in/out)
static tracewan_report_t reports[2];

// dropped in this report period
static uint64_t packets_dropped = 0;
static uint64_t packets_dropped_prev = 0;
static uint64_t packets_ignored = 0;

/* Clear out the reports. */
static void tracewan_reset_report() {
  int dir;
  for (dir = 0; dir < 2; dir++) {  
    reports[dir].count = 0;
    reports[dir].bytes = 0;
    reports[dir].min = -1.0;
    reports[dir].max = -1.0;
    reports[dir].sum = 0;
    reports[dir].ssq = 0;
    reports[dir].mean = 0;
    reports[dir].std = 0;    
    reports[dir].cv = 0;    
  }
}

/* Calculate stats. */
static void tracewan_finalize_report() {
  int dir;
  for (dir = 0; dir < 2; dir++) {  
    if (reports[dir].count > 2) {
      reports[dir].mean = reports[dir].sum/(reports[dir].count-1);
      reports[dir].std = _stddev((reports[dir].count-1), 
				 reports[dir].sum, 
				 reports[dir].ssq);
      if (reports[dir].mean > 0)
	reports[dir].cv = reports[dir].std / reports[dir].mean;
      if (reports[dir].min < 0)
	reports[dir].min = 0.0;
      if (reports[dir].max < 0)
	reports[dir].max = 0.0;
    }
  }
}

/* Substract two 'struct timespec' timestamps and return
 * the result as double in microseconds.
 */
static double timespec_subtract(struct timespec *x, struct timespec *y) {
  double x1 = (x->tv_sec * 1000000.0) + x->tv_nsec / 1000.0;
  double y1 = (y->tv_sec * 1000000.0) + y->tv_nsec / 1000.0;
  return (x1 - y1);
}

/* Handle packet. */
static void tracewan_packet_callback(libtrace_packet_t *packet, 
				     struct timespec *prev_ts) {
    int dir;
    double ia;
    struct timespec ts;

    dir = trace_get_direction(packet);   

    if (dir == TRACE_OUTGOING || dir == TRACE_INCOMING) {
      pthread_mutex_lock(&report_mutex);

      ts = trace_get_timespec(packet);

      reports[dir].count++;
      reports[dir].bytes += trace_get_wire_length(packet);

      if (prev_ts->tv_sec) {
	ia = timespec_subtract(&ts, prev_ts); // in microsec
	reports[dir].sum += ia;
	reports[dir].ssq += (ia*ia);

	if (reports[dir].min < 0 || ia < reports[dir].min)
	  reports[dir].min = ia;

	if (reports[dir].max < 0 || ia > reports[dir].max)
	  reports[dir].max = ia;
      }

      pthread_mutex_unlock(&report_mutex);
    } else {
      pthread_mutex_lock(&stat_mutex);
      ++packets_ignored;
      pthread_mutex_unlock(&stat_mutex);
    }
}

/* Main capture thread loop. */
static int tracewan_run_loop(void) {
  libtrace_err_t err;
  libtrace_packet_t *packet;
  libtrace_t *trace;
  struct timespec prev_ts = {0, 0};
  int snaplen = TRACE_SNAPLEN;

  /* Don't block any signals */
  {
    sigset_t sigmask;
    sigemptyset (&sigmask);
    pthread_sigmask (SIG_SETMASK, &sigmask, NULL);
  }

  DEBUG("tracewan plugin: Opening trace `%s' ..", 
	((interface != NULL) ? interface : "not set"));

  trace = trace_create(interface);

  if (trace_is_err(trace)) {
    err = trace_get_err(trace);
    ERROR("tracewan plugin: Opening trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
    return (err.err_num);
  }

  if (trace_config(trace,TRACE_OPTION_SNAPLEN,&snaplen)) {
    ERROR("tracewan plugin: Setting snaplen for `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
  }

  if (trace_start(trace)) {
    err = trace_get_err(trace);
    ERROR("tracewan plugin: Starting trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
    trace_destroy(trace);
    return (err.err_num);
  }

  packet = trace_create_packet();

  while (trace_read_packet(trace, packet)>0) {
    tracewan_packet_callback(packet, &prev_ts);
    prev_ts = trace_get_timespec(packet);

    // FIXME: avoid doing this / packet ?
    pthread_mutex_lock(&stat_mutex);
    packets_dropped = trace_get_dropped_packets(trace);
    pthread_mutex_unlock(&stat_mutex);
  }

  trace_destroy_packet(packet);
    
  if (trace_is_err(trace)) {
    err = trace_get_err(trace);
    ERROR("tracewan plugin: Reading trace `%s' failed: %s",
	  ((interface != NULL) ? interface : "not set"), 
	  err.problem);
  }

  trace_destroy(trace);
  return (0);
}

static int tracewan_sleep_one_interval(void) {
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

static void *tracewan_child_loop(__attribute__((unused)) void *dummy) {
  int status = 0;
  while (42) {
    status = tracewan_run_loop();
    if (status != TRACE_ERR_INIT_FAILED)
      break;
    tracewan_sleep_one_interval();
  }
  listen_thread_init = 0;
  return (NULL);
}

static void submit_gauge(const char *type, 
			 const char *type_instance, 
			 gauge_t out, gauge_t in) {
  value_t values[2];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = out;
  values[1].gauge = in;
  
  vl.values = values;
  vl.values_len = 2;
  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "tracewan", sizeof (vl.plugin));
  sstrncpy (vl.type, type, sizeof (vl.type));
  sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
  
  plugin_dispatch_values (&vl);
}

static void submit_gauge_value(const char *type, 
			       const char *type_instance, 
			       gauge_t value) {
  value_t values[1];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = value;
  
  vl.values = values;
  vl.values_len = 1;
  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "tracewan", sizeof (vl.plugin));
  sstrncpy (vl.type, type, sizeof (vl.type));
  sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
  
  plugin_dispatch_values (&vl);
}

static int tracewan_config(const char *key, const char *value) {
  if (strcasecmp(key, "Interface") == 0) {
    if (interface != NULL)
      free(interface);

    if ((interface = strdup(value)) == NULL)
      return (1);
  }
  return (0);
}

static int tracewan_init(void) {
  int status;

  pthread_mutex_lock(&report_mutex);
  tracewan_reset_report();
  pthread_mutex_unlock(&report_mutex);

  if (listen_thread_init != 0)
    return (-1);

  status = plugin_thread_create(&listen_thread, 
				NULL, 
				tracewan_child_loop,
				(void *) 0);

  if (status != 0) {
    char errbuf[1024];
    ERROR("tracewan plugin: pthread_create failed: %s",
	  sstrerror(errno, errbuf, sizeof (errbuf)));
    return (-1);
  }

  listen_thread_init = 1;

  return (0);
}

static int tracewan_read(void) {
  int dir;
  tracewan_report_t tmp[2];
  uint64_t drop, ignore;

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

  // packets with unknown direction
  ignore = packets_ignored;
  packets_ignored = 0;

  pthread_mutex_unlock(&stat_mutex);

  // get a copy of the report and reset
  pthread_mutex_lock(&report_mutex);
  tracewan_finalize_report();
  for (dir = 0; dir < 2; dir++) {  
    tmp[dir] = reports[dir];
  }
  tracewan_reset_report();
  pthread_mutex_unlock(&report_mutex);

  // submit values
  submit_gauge("trace_stats", "packets", 
	       tmp[TRACE_OUTGOING].count, 
	       tmp[TRACE_INCOMING].count); 

  submit_gauge("trace_stats", "octets", 
	       tmp[TRACE_OUTGOING].bytes, 
	       tmp[TRACE_INCOMING].bytes); 

  submit_gauge("trace_pktiv", "min", 
	       tmp[TRACE_OUTGOING].min, 
	       tmp[TRACE_INCOMING].min); 

  submit_gauge("trace_pktiv", "max", 
	       tmp[TRACE_OUTGOING].max, 
	       tmp[TRACE_INCOMING].max); 

  submit_gauge("trace_pktiv", "mean", 
	       tmp[TRACE_OUTGOING].mean, 
	       tmp[TRACE_INCOMING].mean); 

  submit_gauge("trace_pktiv", "std", 
	       tmp[TRACE_OUTGOING].std, 
	       tmp[TRACE_INCOMING].std); 
  
  submit_gauge("trace_pktiv", "cv", 
	       tmp[TRACE_OUTGOING].cv, 
	       tmp[TRACE_INCOMING].cv); 

  if (drop != UINT64_MAX)
    submit_gauge_value("trace_mod_stats", "dropped", drop);
  submit_gauge_value("trace_mod_stats", "ignored", ignore);

  return (0);
}

void module_register (void) {
  plugin_register_config("tracewan", 
			 tracewan_config, 
			 config_keys, 
			 config_keys_num);
  plugin_register_init ("tracewan", tracewan_init);
  plugin_register_read ("tracewan", tracewan_read);
}
