/* RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "keychain.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"

#include "ripd/ripd.h"

/* ripd options. */
static struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "retain",      no_argument,       NULL, 'r'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* ripd privileges */
static zebra_capabilities_t _caps_p [] = 
{
  ZCAP_RAW,
  ZCAP_BIND
};

struct zebra_privs_t ripd_privs =
{
  _caps_p,
  NULL,
  2,
  0,
#if defined(QUAGGA_USER)
  QUAGGA_USER,
#else
  NULL,  
#endif
#if defined QUAGGA_GROUP
  QUAGGA_GROUP,
#else
  NULL,
#endif
#ifdef VTY_GROUP
  VTY_GROUP,
#else
  NULL,  
#endif
  NULL,
  NULL
};

/* Configuration file and directory. */
static char config_default[] = SYSCONFDIR RIPD_DEFAULT_CONFIG;
char *config_file_ripd ;

/* ripd program name */

/* Route retain mode flag. */
int retain_mode_ripd ;

/* RIP VTY bind address. */
char *vty_addr_ripd ;

/* RIP VTY connection port. */
int vty_port_ripd ;

/* Master of threads. */
struct thread_master *master_ripd;

/* Process ID saved for use by init system */
const char *pid_file_ripd ;

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages RIP version 1 and 2.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-r, --retain       When program terminates, retain added route by ripd.\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");
  rip_clean ();
  rip_reset ();
  zlog_info ("ripd restarting!");

  /* Reload config file. */
  vty_read_config (config_file, config_default);

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, RIP_VTYSH_PATH);

  /* Try to return to normal operation. */
}

/* SIGINT handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");

  if (! retain_mode)
    rip_clean ();

  exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t ripd_signals[] =
{
  { 
    SIGHUP,
    &sighup,
    0
  },
  { 
    SIGUSR1,
    &sigusr1,
    0
  },
  {
    SIGINT,
    &sigint,
    0
  },
  {
    SIGTERM,
    &sigint,
    0
  },
};  

/* Main routine of ripd. */
int
ripd_main_entry (int argc, char **argv)
{
  char *p;
  int daemon_mode = 0;
  char *progname;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* Get program name. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* First of all we need logging init. */
  zlog_default = openzlog (progname, ZLOG_RIP,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  /* Command line option parse. */
  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "df:i:hA:P:u:g:rv", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and ripd not
             listening on rip port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : RIP_VTY_PORT);
	  break;
	case 'r':
	  retain_mode = 1;
	  break;
	case 'u':
	  ripd_privs.user = optarg;
	  break;
	case 'g':
	  ripd_privs.group = optarg;
	  break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Prepare master thread. */
  master = thread_master_create ();

  /* Library initialization. */
  zprivs_init (&ripd_privs);
  signal_init (master, Q_SIGC(ripd_signals), ripd_signals);
  cmd_init (1);
  vty_init (master);
  memory_init ();
  keychain_init ();

  /* RIP related initialization. */
  rip_init ();
  rip_if_init ();
  rip_zclient_init ();
  rip_peer_init ();

  /* Sort all installed commands. */
  sort_node ();

  /* Get configuration file. */
  vty_read_config (config_file, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Pid file create. */
  pid_output (pid_file);

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, RIP_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("RIPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}
