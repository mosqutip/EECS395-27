#include <stdio.h>
#include "mytypes.h"
#include "local_scan.h"
#include "exim.h"
BOOL    tls_active             = -1;
int     tls_bits               = 0;
BOOL    tls_certificate_verified = FALSE;
uschar *tls_cipher             = NULL;
BOOL    tls_on_connect         = FALSE;
uschar *tls_on_connect_ports   = NULL;
uschar *tls_peerdn             = NULL;
#include "macros.h"
BOOL    tls_active             = -1;
typedef int BOOL;
typedef unsigned char uschar;
typedef long int time_t;
typedef struct address_item_propagated {
  uschar *address_data;           /* arbitrary data to keep with the address */
  uschar *domain_data;            /* from "domains" lookup */
  uschar *localpart_data;         /* from "local_parts" lookup */
  uschar *errors_address;         /* where to send errors (NULL => sender) */
  header_line *extra_headers;     /* additional headers */
  uschar *remove_headers;         /* list of those to remove */

  #ifdef EXPERIMENTAL_SRS
  uschar *srs_sender;             /* Change return path when delivering */
  #endif
} address_item_propagated;
typedef struct retry_item {
  struct retry_item *next;        /* for chaining */
  uschar *key;                    /* string identifying host/address/message */
  int     basic_errno;            /* error code for this destination */
  int     more_errno;             /* additional error information */
  uschar *message;                /* local error message */
  int     flags;                  /* see below */
} retry_item;
typedef struct reply_item {
  uschar *from;                   /* ) */
  uschar *reply_to;               /* ) */
  uschar *to;                     /* ) */
  uschar *cc;                     /* ) specific header fields */
  uschar *bcc;                    /* ) */
  uschar *subject;                /* ) */
  uschar *headers;                /* misc other headers, concatenated */
  uschar *text;                   /* text string body */
  uschar *file;                   /* file body */
  BOOL    file_expand;            /* expand the body */
  int     expand_forbid;          /* expansion lockout flags */
  uschar *logfile;                /* file to keep a log in */
  uschar *oncelog;                /* file to keep records in for once only */
  time_t  once_repeat;            /* time to repeat "once only" */
  BOOL    return_message;         /* send back the original message */
} reply_item;
typedef struct host_item {
  struct host_item *next;
  uschar *name;                   /* Host name */
  uschar *address;                /* IP address in text form */
  int     port;                   /* port value in host order (if SRV lookup) */
  int     mx;                     /* MX value if found via MX records */
  int     sort_key;               /* MX*1000 plus random "fraction" */
  int     status;                 /* Usable, unusable, or unknown */
  int     why;                    /* Why host is unusable */
  int     last_try;               /* Time of last try if known */
} host_item;
typedef struct rewrite_rule {
  struct rewrite_rule *next;
  int     flags;
  uschar *key;
  uschar *replacement;
} rewrite_rule;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef struct transport_instance {
  struct transport_instance *next;
  uschar *name;                   /* Instance name */
  struct transport_info *info;    /* Info for this driver */
  void *options_block;            /* Pointer to private options */
  uschar *driver_name;            /* Must be first */
  int   (*setup)(                 /* Setup entry point */
    struct transport_instance *,
    struct address_item *,
    struct transport_feedback *,  /* For passing back config data */
    uid_t,                        /* The uid that will be used */
    gid_t,                        /* The gid that will be used */
    uschar **);                   /* For an error message */
                                  /**************************************/
  int     batch_max;              /* )                                  */
  uschar *batch_id;               /* )                                  */
  uschar *home_dir;               /* ) Used only for local transports   */
  uschar *current_dir;            /* )                                  */
                                  /**************************************/
  BOOL    multi_domain;           /* )                                  */
  BOOL    overrides_hosts;        /* ) Used only for remote transports  */
  int     max_addresses;          /* )                                  */
  int     connection_max_messages;/* )                                  */
                                  /**************************************/
  BOOL    deliver_as_creator;     /* Used only by pipe at present */
  BOOL    disable_logging;        /* For very weird requirements */
  BOOL    initgroups;             /* Initialize groups when setting uid */
  BOOL    uid_set;                /* uid is set */
  BOOL    gid_set;                /* gid is set */
  uid_t   uid;
  gid_t   gid;
  uschar *expand_uid;             /* Variable uid */
  uschar *expand_gid;             /* Variable gid */
  uschar *warn_message;           /* Used only by appendfile at present */
  uschar *shadow;                 /* Name of shadow transport */
  uschar *shadow_condition;       /* Condition for running it */
  uschar *filter_command;         /* For on-the-fly-filtering */
  uschar *add_headers;            /* Add these headers */
  uschar *remove_headers;         /* Remove these headers */
  uschar *return_path;            /* Overriding (rewriting) return path */
  uschar *debug_string;           /* Debugging output */
  uschar *message_size_limit;     /* Biggest message this transport handles */
  uschar *headers_rewrite;        /* Rules for rewriting headers */
  rewrite_rule *rewrite_rules;    /* Parsed rewriting rules */
  int     rewrite_existflags;     /* Bits showing which headers are rewritten */
  int     filter_timeout;         /* For transport filter timing */
  BOOL    body_only;              /* Deliver only the body */
  BOOL    delivery_date_add;      /* Add Delivery-Date header */
  BOOL    envelope_to_add;        /* Add Envelope-To header */
  BOOL    headers_only;           /* Deliver only the headers */
  BOOL    rcpt_include_affixes;   /* TRUE to retain affixes in RCPT commands */
  BOOL    return_path_add;        /* Add Return-Path header */
  BOOL    return_output;          /* TRUE if output should always be returned */
  BOOL    return_fail_output;     /* ditto, but only on failure */
  BOOL    log_output;             /* Similarly for logging */
  BOOL    log_fail_output;
  BOOL    log_defer_output;
  BOOL    retry_use_local_part;   /* Defaults true for local, false for remote */
} transport_instance;
typedef struct router_instance {
  struct router_instance *next;
  uschar *name;
  struct router_info *info;
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* Must be first */

  uschar *address_data;           /* Arbitrary data */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  uschar *bmi_rule;               /* Brightmail AntiSpam rule checking */
#endif
  uschar *cannot_route_message;   /* Used when routing fails */
  uschar *condition;              /* General condition */
  uschar *current_directory;      /* For use during delivery */
  uschar *debug_string;           /* Debugging output */
  uschar *domains;                /* Specific domains */
  uschar *errors_to;              /* Errors address */
  uschar *expand_gid;             /* Expanded gid string */
  uschar *expand_uid;             /* Expanded uid string */
  uschar *expand_more;            /* Expanded more string */
  uschar *expand_unseen;          /* Expanded unseen string */
  uschar *extra_headers;          /* Additional headers */
  uschar *fallback_hosts;         /* For remote transports (text list) */
  uschar *home_directory;         /* For use during delivery */
  uschar *ignore_target_hosts;    /* Target hosts to ignore */
  uschar *local_parts;            /* Specific local parts */
  uschar *pass_router_name;       /* Router for passed address */
  uschar *prefix;                 /* Address prefix */
  uschar *redirect_router_name;   /* Router for generated address */
  uschar *remove_headers;         /* Removed headers */
  uschar *require_files;          /* File checks before router is run */
  uschar *router_home_directory;  /* For use while routing */
  uschar *self;                   /* Text option for handling self reference */
  uschar *senders;                /* Specific senders */
  uschar *suffix;                 /* Address suffix */
  uschar *translate_ip_address;   /* IP address translation fudgery */
  uschar *transport_name;         /* Transport name */

  BOOL    address_test;           /* Use this router when testing addresses */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  BOOL    bmi_deliver_alternate;  /* TRUE => BMI said that message should be delivered to alternate location */
  BOOL    bmi_deliver_default;    /* TRUE => BMI said that message should be delivered to default location */
  BOOL    bmi_dont_deliver;       /* TRUE => BMI said that message should not be delivered at all */
#endif
  BOOL    expn;                   /* Use this router when processing EXPN */
  BOOL    caseful_local_part;     /* TRUE => don't lowercase */
  BOOL    check_local_user;       /* TRUE => check local user */
  BOOL    disable_logging;        /* For very weird requirements */
  BOOL    fail_verify_recipient;  /* Fail verify if recipient match this router */
  BOOL    fail_verify_sender;     /* Fail verify if sender match this router */
  BOOL    gid_set;                /* Flag to indicate gid is set */
  BOOL    initgroups;             /* TRUE if initgroups is required */
  BOOL    log_as_local;           /* TRUE logs as a local delivery */
  BOOL    more;                   /* If FALSE, do no more if this one fails */
  BOOL    pass_on_timeout;        /* Treat timeout DEFERs as fails */
  BOOL    prefix_optional;        /* Just what it says */
  BOOL    repeat_use;             /* If FALSE, skip if ancestor used it */
  BOOL    retry_use_local_part;   /* Just what it says */
  BOOL    same_domain_copy_routing; /* TRUE => copy routing for same domain */
  BOOL    self_rewrite;           /* TRUE to rewrite headers if making local */
  BOOL    suffix_optional;        /* As it says */
  BOOL    verify_only;            /* Skip this router if not verifying */
  BOOL    verify_recipient;       /* Use this router when verifying a recipient*/
  BOOL    verify_sender;          /* Use this router when verifying a sender */
  BOOL    uid_set;                /* Flag to indicate uid is set */
  BOOL    unseen;                 /* If TRUE carry on, even after success */

  int     self_code;              /* Encoded version of "self" */
  uid_t   uid;                    /* Fixed uid value */
  gid_t   gid;                    /* Fixed gid value */

  host_item *fallback_hostlist;   /* For remote transport (block chain) */
  transport_instance *transport;  /* Transport block (when found) */
  struct router_instance *pass_router; /* Actual router for passed address */
  struct router_instance *redirect_router; /* Actual router for generated address */
} router_instance;
typedef struct address_item {
  struct address_item *next;      /* for chaining addresses */
  struct address_item *parent;    /* parent address */
  struct address_item *first;     /* points to first after group delivery */
  struct address_item *dupof;     /* points to address this is a duplicate of */

  router_instance *start_router;  /* generated address starts here */
  router_instance *router;        /* the router that routed */
  transport_instance *transport;  /* the transport to use */

  host_item *host_list;           /* host data for the transport */
  host_item *host_used;           /* host that took delivery or failed hard */
  host_item *fallback_hosts;      /* to try if delivery defers */

  reply_item *reply;              /* data for autoreply */
  retry_item *retries;            /* chain of retry information */

  uschar *address;                /* address being delivered or routed */
  uschar *unique;                 /* used for disambiguating */
  uschar *cc_local_part;          /* caseful local part */
  uschar *lc_local_part;          /* lowercased local part */
  uschar *local_part;             /* points to cc or lc version */
  uschar *prefix;                 /* stripped prefix of local part */
  uschar *suffix;                 /* stripped suffix of local part */
  uschar *domain;                 /* working domain (lower cased) */

  uschar *address_retry_key;      /* retry key including full address */
  uschar *domain_retry_key;       /* retry key for domain only */

  uschar *current_dir;            /* current directory for transporting */
  uschar *home_dir;               /* home directory for transporting */
  uschar *message;                /* error message */
  uschar *user_message;           /* error message that can be sent over SMTP
                                     or quoted in bounce message */
  uschar *onetime_parent;         /* saved original parent for onetime */
  uschar **pipe_expandn;          /* numeric expansions for pipe from filter */
  uschar *return_filename;        /* name of return file */
  uschar *self_hostname;          /* after self=pass */
  uschar *shadow_message;         /* info about shadow transporting */

  #ifdef SUPPORT_TLS
  uschar *cipher;                 /* Cipher used for transport */
  uschar *peerdn;                 /* DN of server's certificate */
  #endif

  uid_t   uid;                    /* uid for transporting */
  gid_t   gid;                    /* gid for transporting */

  unsigned int flags;             /* a row of bits, defined above */
  unsigned int domain_cache[(MAX_NAMED_LIST * 2)/32];
  unsigned int localpart_cache[(MAX_NAMED_LIST * 2)/32];
  int     mode;                   /* mode for local transporting to a file */
  int     more_errno;             /* additional error information */
                                  /* (may need to hold a timestamp) */

  short int basic_errno;          /* status after failure */
  short int child_count;          /* number of child addresses */
  short int return_file;          /* fileno of return data file */
  short int special_action;       /* ( used when when deferred or failed */
                                  /* (  also  */
                                  /* ( contains = or - when successful SMTP delivered */
                                  /* (  also  */
                                  /* ( contains verify rc in sender verify cache */
  short int transport_return;     /* result of delivery attempt */
  address_item_propagated p;      /* fields that are propagated to children */
} address_item;
#ifdef EXIM_PERL
uschar *opt_perl_startup       = NULL;
BOOL    opt_perl_at_start      = FALSE;
BOOL    opt_perl_started       = FALSE;
#endif

#ifdef EXPAND_DLFUNC
tree_node *dlobj_anchor        = NULL;
#endif

#ifdef LOOKUP_IBASE
uschar *ibase_servers          = NULL;
#endif

#ifdef LOOKUP_LDAP
uschar *eldap_ca_cert_dir      = NULL;
uschar *eldap_ca_cert_file     = NULL;
uschar *eldap_cert_file        = NULL;
uschar *eldap_cert_key         = NULL;
uschar *eldap_cipher_suite     = NULL;
uschar *eldap_default_servers  = NULL;
uschar *eldap_require_cert     = NULL;
int     eldap_version          = -1;
BOOL    eldap_start_tls        = FALSE;
#endif

#ifdef LOOKUP_MYSQL
uschar *mysql_servers          = NULL;
#endif

#ifdef LOOKUP_ORACLE
uschar *oracle_servers         = NULL;
#endif

#ifdef LOOKUP_PGSQL
uschar *pgsql_servers          = NULL;
#endif

#ifdef LOOKUP_SQLITE
int     sqlite_lock_timeout    = 5;
#endif

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
BOOL    move_frozen_messages   = FALSE;
#endif

/* These variables are outside the #ifdef because it keeps the code less
cluttered in several places (e.g. during logging) if we can always refer to
them. Also, the tls_ variables are now always visible. */

BOOL    tls_active             = -1;
int     tls_bits               = 0;
BOOL    tls_certificate_verified = FALSE;
uschar *tls_cipher             = NULL;
BOOL    tls_on_connect         = FALSE;
uschar *tls_on_connect_ports   = NULL;
uschar *tls_peerdn             = NULL;

#ifdef SUPPORT_TLS
BOOL    gnutls_compat_mode     = FALSE;
uschar *gnutls_require_mac     = NULL;
uschar *gnutls_require_kx      = NULL;
uschar *gnutls_require_proto   = NULL;
uschar *openssl_options        = NULL;
const pcre *regex_STARTTLS     = NULL;
uschar *tls_advertise_hosts    = NULL;    /* This is deliberate */
uschar *tls_certificate        = NULL;
uschar *tls_crl                = NULL;
/* This default matches NSS DH_MAX_P_BITS value at current time (2012), because
that's the interop problem which has been observed: GnuTLS suggesting a higher
bit-count as "NORMAL" (2432) and Thunderbird dropping connection. */
int     tls_dh_max_bits        = 2236;
uschar *tls_dhparam            = NULL;
#if defined(EXPERIMENTAL_OCSP) && !defined(USE_GNUTLS)
uschar *tls_ocsp_file          = NULL;
#endif
BOOL    tls_offered            = FALSE;
uschar *tls_privatekey         = NULL;
BOOL    tls_remember_esmtp     = FALSE;
uschar *tls_require_ciphers    = NULL;
uschar *tls_sni                = NULL;
uschar *tls_try_verify_hosts   = NULL;
uschar *tls_verify_certificates= NULL;
uschar *tls_verify_hosts       = NULL;
#endif


/* Input-reading functions for messages, so we can use special ones for
incoming TCP/IP. The defaults use stdin. We never need these for any
stand-alone tests. */

#ifndef STAND_ALONE
int
stdin_getc(void)
{
return getc(stdin);
}

int
stdin_ungetc(int c)
{
return ungetc(c, stdin);
}

int
stdin_feof(void)
{
return feof(stdin);
}

int
stdin_ferror(void)
{
return ferror(stdin);
}


int (*receive_getc)(void)      = stdin_getc;
int (*receive_ungetc)(int)     = stdin_ungetc;
int (*receive_feof)(void)      = stdin_feof;
int (*receive_ferror)(void)    = stdin_ferror;
BOOL (*receive_smtp_buffered)(void) = NULL;   /* Only used for SMTP */
#endif


/* List of per-address expansion variables for clearing and saving/restoring
when verifying one address while routing/verifying another. We have to have
the size explicit, because it is referenced from more than one module. */

typedef struct tree_node {
  struct tree_node *left;         /* pointer to left child */
  struct tree_node *right;        /* pointer to right child */
  union
    {
    void  *ptr;                   /* pointer to data */
    int val;                      /* or integer data */
    } data;
  uschar  balance;                /* balancing factor */
  uschar  name[1];                /* node name - variable length */
} tree_node;

BOOL    delivery_date_remove   = TRUE;
uschar *deliver_address_data   = NULL;
int     deliver_datafile       = -1;
uschar *deliver_domain         = NULL;
uschar *deliver_domain_data    = NULL;
uschar *deliver_domain_orig    = NULL;
uschar *deliver_domain_parent  = NULL;
BOOL    deliver_drop_privilege = FALSE;
BOOL    deliver_firsttime      = FALSE;
BOOL    deliver_force          = FALSE;
BOOL    deliver_freeze         = FALSE;
int     deliver_frozen_at      = 0;
uschar *deliver_home           = NULL;
uschar *deliver_host           = NULL;
uschar *deliver_host_address   = NULL;
uschar *deliver_in_buffer      = NULL;
ino_t   deliver_inode          = 0;
uschar *deliver_localpart      = NULL;
uschar *deliver_localpart_data = NULL;
uschar *deliver_localpart_orig = NULL;
uschar *deliver_localpart_parent = NULL;
uschar *deliver_localpart_prefix = NULL;
uschar *deliver_localpart_suffix = NULL;
BOOL    deliver_force_thaw     = FALSE;
BOOL    deliver_manual_thaw    = FALSE;
uschar *deliver_out_buffer     = NULL;
int     deliver_queue_load_max = -1;
address_item  *deliver_recipients = NULL;
uschar *deliver_selectstring   = NULL;
BOOL    deliver_selectstring_regex = FALSE;
uschar *deliver_selectstring_sender = NULL;
BOOL    deliver_selectstring_sender_regex = FALSE;
uschar *address_file           = NULL;
uschar *address_pipe           = NULL;
BOOL    address_test_mode      = FALSE;
tree_node *addresslist_anchor  = NULL;
int     addresslist_count      = 0;
gid_t  *admin_groups           = NULL;
BOOL    admin_user             = FALSE;
BOOL    allow_auth_unadvertised= FALSE;
BOOL    allow_domain_literals  = FALSE;
BOOL    allow_mx_to_ip         = FALSE;
BOOL    allow_unqualified_recipient = TRUE;    /* For local messages */
BOOL    allow_unqualified_sender = TRUE;       /* Reset for SMTP */
BOOL    allow_utf8_domains     = FALSE;
uschar *authenticated_id       = NULL;
uschar *authenticated_sender   = NULL;
BOOL    authentication_failed  = FALSE;
typedef struct auth_instance {
  struct auth_instance *next;
  uschar *name;                   /* Exim instance name */
  struct auth_info *info;         /* Pointer to driver info block */
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* Must be first */
  uschar *advertise_condition;    /* Are we going to advertise this?*/
  uschar *client_condition;       /* Should the client try this? */
  uschar *public_name;            /* Advertised name */
  uschar *set_id;                 /* String to set as authenticated id */
  uschar *mail_auth_condition;    /* Condition for AUTH on MAIL command */
  uschar *server_debug_string;    /* Debugging output */
  uschar *server_condition;       /* Authorization condition */
  BOOL    client;                 /* TRUE if client option(s) set */
  BOOL    server;                 /* TRUE if server options(s) set */
  BOOL    advertised;             /* Set TRUE when advertised */
} auth_instance;
auth_instance  *auths          = NULL;
uschar *auth_advertise_hosts   = US"*";
uschar *self_hostname          = NULL;
uschar **address_expansions[ADDRESS_EXPANSIONS_COUNT] = {
  &deliver_address_data,
  &deliver_domain,
  &deliver_domain_data,
  &deliver_domain_orig,
  &deliver_domain_parent,
  &deliver_localpart,
  &deliver_localpart_data,
  &deliver_localpart_orig,
  &deliver_localpart_parent,
  &deliver_localpart_prefix,
  &deliver_localpart_suffix,
  (uschar **)(&deliver_recipients),
  &deliver_host,
  &deliver_home,
  &address_file,
  &address_pipe,
  &self_hostname,
  NULL };

int address_expansions_count = sizeof(address_expansions)/sizeof(uschar **);

/* General global variables */
header_line *acl_added_headers = NULL;
tree_node *acl_anchor          = NULL;

uschar *acl_not_smtp           = NULL;
#ifdef WITH_CONTENT_SCAN
uschar *acl_not_smtp_mime      = NULL;
#endif
uschar *acl_not_smtp_start     = NULL;

uschar *acl_smtp_auth          = NULL;
uschar *acl_smtp_connect       = NULL;
uschar *acl_smtp_data          = NULL;
#ifndef DISABLE_DKIM
uschar *acl_smtp_dkim          = NULL;
#endif
uschar *acl_smtp_etrn          = NULL;
uschar *acl_smtp_expn          = NULL;
uschar *acl_smtp_helo          = NULL;
uschar *acl_smtp_mail          = NULL;
uschar *acl_smtp_mailauth      = NULL;
#ifdef WITH_CONTENT_SCAN
uschar *acl_smtp_mime          = NULL;
#endif
uschar *acl_smtp_notquit       = NULL;
uschar *acl_smtp_predata       = NULL;
uschar *acl_smtp_quit          = NULL;
uschar *acl_smtp_rcpt          = NULL;
uschar *acl_smtp_starttls      = NULL;
uschar *acl_smtp_vrfy          = NULL;

BOOL    acl_temp_details       = FALSE;
tree_node *acl_var_c           = NULL;
tree_node *acl_var_m           = NULL;
typedef struct string_item {
  struct string_item *next;
  uschar *text;
} string_item;
uschar *acl_verify_message     = NULL;
string_item *acl_warn_logged   = NULL;

/* Names of SMTP places for use in ACL error messages, and corresponding SMTP
error codes - keep in step with definitions of ACL_WHERE_xxxx in macros.h. */

uschar *acl_wherenames[]       = { US"RCPT",
                                   US"MAIL",
                                   US"PREDATA",
                                   US"MIME",
                                   US"DKIM",
                                   US"DATA",
                                   US"non-SMTP",
                                   US"AUTH",
                                   US"connection",
                                   US"ETRN",
                                   US"EXPN",
                                   US"EHLO or HELO",
                                   US"MAILAUTH",
                                   US"non-SMTP-start",
                                   US"NOTQUIT",
                                   US"QUIT",
                                   US"STARTTLS",
                                   US"VRFY"
                                 };

uschar *acl_wherecodes[]       = { US"550",     /* RCPT */
                                   US"550",     /* MAIL */
                                   US"550",     /* PREDATA */
                                   US"550",     /* MIME */
                                   US"550",     /* DKIM */
                                   US"550",     /* DATA */
                                   US"0",       /* not SMTP; not relevant */
                                   US"503",     /* AUTH */
                                   US"550",     /* connect */
                                   US"458",     /* ETRN */
                                   US"550",     /* EXPN */
                                   US"550",     /* HELO/EHLO */
                                   US"0",       /* MAILAUTH; not relevant */
                                   US"0",       /* not SMTP; not relevant */
                                   US"0",       /* NOTQUIT; not relevant */
                                   US"0",       /* QUIT; not relevant */
                                   US"550",     /* STARTTLS */
                                   US"252"      /* VRFY */
                                 };

BOOL    active_local_from_check = FALSE;
BOOL    active_local_sender_retain = FALSE;
BOOL    accept_8bitmime        = TRUE; /* deliberately not RFC compliant */
address_item  *addr_duplicate  = NULL;

address_item address_defaults = {
  NULL,                 /* next */
  NULL,                 /* parent */
  NULL,                 /* first */
  NULL,                 /* dupof */
  NULL,                 /* start_router */
  NULL,                 /* router */
  NULL,                 /* transport */
  NULL,                 /* host_list */
  NULL,                 /* host_used */
  NULL,                 /* fallback_hosts */
  NULL,                 /* reply */
  NULL,                 /* retries */
  NULL,                 /* address */
  NULL,                 /* unique */
  NULL,                 /* cc_local_part */
  NULL,                 /* lc_local_part */
  NULL,                 /* local_part */
  NULL,                 /* prefix */
  NULL,                 /* suffix */
  NULL,                 /* domain */
  NULL,                 /* address_retry_key */
  NULL,                 /* domain_retry_key */
  NULL,                 /* current_dir */
  NULL,                 /* home_dir */
  NULL,                 /* message */
  NULL,                 /* user_message */
  NULL,                 /* onetime_parent */
  NULL,                 /* pipe_expandn */
  NULL,                 /* return_filename */
  NULL,                 /* self_hostname */
  NULL,                 /* shadow_message */
  #ifdef SUPPORT_TLS
  NULL,                 /* cipher */
  NULL,                 /* peerdn */
  #endif
  (uid_t)(-1),          /* uid */
  (gid_t)(-1),          /* gid */
  0,                    /* flags */
  { 0 },                /* domain_cache - any larger array should be zeroed */
  { 0 },                /* localpart_cache - ditto */
  -1,                   /* mode */
  0,                    /* more_errno */
  ERRNO_UNKNOWNERROR,   /* basic_errno */
  0,                    /* child_count */
  -1,                   /* return_file */
  SPECIAL_NONE,         /* special_action */
  DEFER,                /* transport_return */
  {                     /* fields that are propagated to children */
    NULL,               /* address_data */
    NULL,               /* domain_data */
    NULL,               /* localpart_data */
    NULL,               /* errors_address */
    NULL,               /* extra_headers */
    NULL,               /* remove_headers */
#ifdef EXPERIMENTAL_SRS
    NULL,               /* srs_sender */
#endif
  }
};

uschar *address_file           = NULL;
uschar *address_pipe           = NULL;
BOOL    address_test_mode      = FALSE;
tree_node *addresslist_anchor  = NULL;
int     addresslist_count      = 0;
gid_t  *admin_groups           = NULL;
BOOL    admin_user             = FALSE;
BOOL    allow_auth_unadvertised= FALSE;
BOOL    allow_domain_literals  = FALSE;
BOOL    allow_mx_to_ip         = FALSE;
BOOL    allow_unqualified_recipient = TRUE;    /* For local messages */
BOOL    allow_unqualified_sender = TRUE;       /* Reset for SMTP */
BOOL    allow_utf8_domains     = FALSE;
uschar *authenticated_id       = NULL;
uschar *authenticated_sender   = NULL;
BOOL    authentication_failed  = FALSE;
typedef struct auth_instance {
  struct auth_instance *next;
  uschar *name;                   /* Exim instance name */
  struct auth_info *info;         /* Pointer to driver info block */
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* Must be first */
  uschar *advertise_condition;    /* Are we going to advertise this?*/
  uschar *client_condition;       /* Should the client try this? */
  uschar *public_name;            /* Advertised name */
  uschar *set_id;                 /* String to set as authenticated id */
  uschar *mail_auth_condition;    /* Condition for AUTH on MAIL command */
  uschar *server_debug_string;    /* Debugging output */
  uschar *server_condition;       /* Authorization condition */
  BOOL    client;                 /* TRUE if client option(s) set */
  BOOL    server;                 /* TRUE if server options(s) set */
  BOOL    advertised;             /* Set TRUE when advertised */
} auth_instance;
auth_instance  *auths          = NULL;
uschar *auth_advertise_hosts   = US"*";
auth_instance auth_defaults    = {
    NULL,                      /* chain pointer */
    NULL,                      /* name */
    NULL,                      /* info */
    NULL,                      /* private options block pointer */
    NULL,                      /* driver_name */
    NULL,                      /* advertise_condition */
    NULL,                      /* client_condition */
    NULL,                      /* public_name */
    NULL,                      /* set_id */
    NULL,                      /* server_mail_auth_condition */
    NULL,                      /* server_debug_string */
    NULL,                      /* server_condition */
    FALSE,                     /* client */
    FALSE,                     /* server */
    FALSE                      /* advertised */
};

uschar *auth_defer_msg         = US"reason not recorded";
uschar *auth_defer_user_msg    = US"";
uschar *auth_vars[AUTH_VARS];
int     auto_thaw              = 0;
#ifdef WITH_CONTENT_SCAN
BOOL    av_failed              = FALSE;
uschar *av_scanner             = US"sophie:/var/run/sophie";  /* AV scanner */
#endif

BOOL    background_daemon      = TRUE;

#if BASE_62 == 62
uschar *base62_chars=
    US"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#else
uschar *base62_chars= US"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
#endif

uschar *bi_command             = NULL;
uschar *big_buffer             = NULL;
int     big_buffer_size        = BIG_BUFFER_SIZE;
#ifdef EXPERIMENTAL_BRIGHTMAIL
uschar *bmi_alt_location       = NULL;
uschar *bmi_base64_tracker_verdict = NULL;
uschar *bmi_base64_verdict     = NULL;
uschar *bmi_config_file        = US"/opt/brightmail/etc/brightmail.cfg";
int     bmi_deliver            = 1;
int     bmi_run                = 0;
uschar *bmi_verdicts           = NULL;
#endif
int     body_linecount         = 0;
int     body_zerocount         = 0;
uschar *bounce_message_file    = NULL;
uschar *bounce_message_text    = NULL;
uschar *bounce_recipient       = NULL;
BOOL    bounce_return_body     = TRUE;
BOOL    bounce_return_message  = TRUE;
int     bounce_return_size_limit = 100*1024;
uschar *bounce_sender_authentication = NULL;
int     bsmtp_transaction_linecount = 0;

int     callout_cache_domain_positive_expire = 7*24*60*60;
int     callout_cache_domain_negative_expire = 3*60*60;
int     callout_cache_positive_expire = 24*60*60;
int     callout_cache_negative_expire = 2*60*60;
uschar *callout_random_local_part = US"$primary_hostname-$tod_epoch-testing";
uschar *check_dns_names_pattern= US"(?i)^(?>(?(1)\\.|())[^\\W](?>[a-z0-9/_-]*[^\\W])?)+(\\.?)$";
int     check_log_inodes       = 0;
int     check_log_space        = 0;
BOOL    check_rfc2047_length   = TRUE;
int     check_spool_inodes     = 0;
int     check_spool_space      = 0;
int     clmacro_count          = 0;
uschar *clmacros[MAX_CLMACROS];
BOOL    config_changed         = FALSE;
FILE   *config_file            = NULL;
uschar *config_filename        = NULL;
int     config_lineno          = 0;
#ifdef CONFIGURE_GROUP
gid_t   config_gid             = CONFIGURE_GROUP;
#endif
uschar *config_main_filelist   = US CONFIGURE_FILE
                         "\0<-----------Space to patch configure_filename->";
uschar *config_main_filename   = NULL;

#ifdef CONFIGURE_OWNER
uid_t   config_uid             = CONFIGURE_OWNER;
#endif

int     connection_max_messages= -1;
uschar *continue_hostname      = NULL;
uschar *continue_host_address  = NULL;
BOOL    continue_more          = FALSE;
int     continue_sequence      = 1;
uschar *continue_transport     = NULL;

uschar *csa_status             = NULL;

BOOL    daemon_listen          = FALSE;
uschar *daemon_smtp_port       = US"smtp";
int     daemon_startup_retries = 9;
int     daemon_startup_sleep   = 30;

#ifdef EXPERIMENTAL_DCC
BOOL    dcc_direct_add_header  = FALSE;
uschar *dcc_header             = NULL;
uschar *dcc_result             = NULL;
uschar *dccifd_address         = US"/usr/local/dcc/var/dccifd";
uschar *dccifd_options         = US"header";
#endif

BOOL    debug_daemon           = FALSE;
int     debug_fd               = -1;
FILE   *debug_file             = NULL;
typedef struct bit_table {
  uschar *name;
  unsigned int bit;
} bit_table;
bit_table debug_options[]      = {
  { US"acl",            D_acl },
  { US"all",            D_all },
  { US"auth",           D_auth },
  { US"deliver",        D_deliver },
  { US"dns",            D_dns },
  { US"dnsbl",          D_dnsbl },
  { US"exec",           D_exec },
  { US"expand",         D_expand },
  { US"filter",         D_filter },
  { US"hints_lookup",   D_hints_lookup },
  { US"host_lookup",    D_host_lookup },
  { US"ident",          D_ident },
  { US"interface",      D_interface },
  { US"lists",          D_lists },
  { US"load",           D_load },
  { US"local_scan",     D_local_scan },
  { US"lookup",         D_lookup },
  { US"memory",         D_memory },
  { US"pid",            D_pid },
  { US"process_info",   D_process_info },
  { US"queue_run",      D_queue_run },
  { US"receive",        D_receive },
  { US"resolver",       D_resolver },
  { US"retry",          D_retry },
  { US"rewrite",        D_rewrite },
  { US"route",          D_route },
  { US"timestamp",      D_timestamp },
  { US"tls",            D_tls },
  { US"transport",      D_transport },
  { US"uid",            D_uid },
  { US"verify",         D_verify }
};
int     debug_options_count    = sizeof(debug_options)/sizeof(bit_table);
unsigned int debug_selector    = 0;
int     delay_warning[DELAY_WARNING_SIZE] = { DELAY_WARNING_SIZE, 1, 24*60*60 };
uschar *delay_warning_condition=
  US"${if or {"
            "{ !eq{$h_list-id:$h_list-post:$h_list-subscribe:}{} }"
            "{ match{$h_precedence:}{(?i)bulk|list|junk} }"
            "{ match{$h_auto-submitted:}{(?i)auto-generated|auto-replied} }"
            "} {no}{yes}}";
BOOL    delivery_date_remove   = TRUE;
uschar *deliver_address_data   = NULL;
int     deliver_datafile       = -1;
uschar *deliver_domain         = NULL;
uschar *deliver_domain_data    = NULL;
uschar *deliver_domain_orig    = NULL;
uschar *deliver_domain_parent  = NULL;
BOOL    deliver_drop_privilege = FALSE;
BOOL    deliver_firsttime      = FALSE;
BOOL    deliver_force          = FALSE;
BOOL    deliver_freeze         = FALSE;
int     deliver_frozen_at      = 0;
uschar *deliver_home           = NULL;
uschar *deliver_host           = NULL;
uschar *deliver_host_address   = NULL;
uschar *deliver_in_buffer      = NULL;
ino_t   deliver_inode          = 0;
uschar *deliver_localpart      = NULL;
uschar *deliver_localpart_data = NULL;
uschar *deliver_localpart_orig = NULL;
uschar *deliver_localpart_parent = NULL;
uschar *deliver_localpart_prefix = NULL;
uschar *deliver_localpart_suffix = NULL;
BOOL    deliver_force_thaw     = FALSE;
BOOL    deliver_manual_thaw    = FALSE;
uschar *deliver_out_buffer     = NULL;
int     deliver_queue_load_max = -1;
address_item  *deliver_recipients = NULL;
uschar *deliver_selectstring   = NULL;
BOOL    deliver_selectstring_regex = FALSE;
uschar *deliver_selectstring_sender = NULL;
BOOL    deliver_selectstring_sender_regex = FALSE;
#ifdef WITH_OLD_DEMIME
int     demime_errorlevel      = 0;
int     demime_ok              = 0;
uschar *demime_reason          = NULL;
#endif
BOOL    disable_callout_flush  = FALSE;
BOOL    disable_delay_flush    = FALSE;
#ifdef ENABLE_DISABLE_FSYNC
BOOL    disable_fsync          = FALSE;
#endif
BOOL    disable_ipv6           = FALSE;
BOOL    disable_logging        = FALSE;

#ifndef DISABLE_DKIM
uschar *dkim_cur_signer          = NULL;
uschar *dkim_signers             = NULL;
uschar *dkim_signing_domain      = NULL;
uschar *dkim_signing_selector    = NULL;
uschar *dkim_verify_signers      = US"$dkim_signers";
BOOL    dkim_collect_input       = FALSE;
BOOL    dkim_disable_verify      = FALSE;
#endif

uschar *dns_again_means_nonexist = NULL;
int     dns_csa_search_limit   = 5;
BOOL    dns_csa_use_reverse    = TRUE;
uschar *dns_ipv4_lookup        = NULL;
int     dns_retrans            = 0;
int     dns_retry              = 0;
int     dns_use_edns0          = -1; /* <0 = not coerced */
uschar *dnslist_domain         = NULL;
uschar *dnslist_matched        = NULL;
uschar *dnslist_text           = NULL;
uschar *dnslist_value          = NULL;
tree_node *domainlist_anchor   = NULL;
int     domainlist_count       = 0;
BOOL    dont_deliver           = FALSE;
BOOL    dot_ends               = TRUE;
BOOL    drop_cr                = FALSE;         /* No longer used */
uschar *dsn_from               = US DEFAULT_DSN_FROM;

BOOL    enable_dollar_recipients = FALSE;
BOOL    envelope_to_remove     = TRUE;
int     errno_quota            = ERRNO_QUOTA;
uschar *errors_copy            = NULL;
int     error_handling         = ERRORS_SENDER;
uschar *errors_reply_to        = NULL;
int     errors_sender_rc       = EXIT_FAILURE;

gid_t   exim_gid               = EXIM_GID;
BOOL    exim_gid_set           = TRUE;          /* This gid is always set */
uschar *exim_path              = US BIN_DIRECTORY "/exim"
                        "\0<---------------Space to patch exim_path->";
uid_t   exim_uid               = EXIM_UID;
BOOL    exim_uid_set           = TRUE;          /* This uid is always set */
int     expand_forbid          = 0;
int     expand_nlength[EXPAND_MAXN+1];
int     expand_nmax            = -1;
uschar *expand_nstring[EXPAND_MAXN+1];
BOOL    expand_string_forcedfail = FALSE;
uschar *expand_string_message;
BOOL    extract_addresses_remove_arguments = TRUE;
uschar *extra_local_interfaces = NULL;

int     fake_response          = OK;
uschar *fake_response_text     = US"Your message has been rejected but is "
                                   "being kept for evaluation.\nIf it was a "
                                   "legitimate message, it may still be "
                                   "delivered to the target recipient(s).";
int     filter_n[FILTER_VARIABLE_COUNT];
BOOL    filter_running         = FALSE;
int     filter_sn[FILTER_VARIABLE_COUNT];
int     filter_test            = FTEST_NONE;
uschar *filter_test_sfile      = NULL;
uschar *filter_test_ufile      = NULL;
uschar *filter_thisaddress     = NULL;
int     finduser_retries       = 0;
#ifdef WITH_OLD_DEMIME
uschar *found_extension        = NULL;
#endif
uid_t   fixed_never_users[]    = { FIXED_NEVER_USERS };
uschar *freeze_tell            = NULL;
uschar *freeze_tell_config     = NULL;
uschar *fudged_queue_times     = US"";

uschar *gecos_name             = NULL;
uschar *gecos_pattern          = NULL;
rewrite_rule  *global_rewrite_rules = NULL;

uschar *headers_charset        = US HEADERS_CHARSET;
int     header_insert_maxlen   = 64 * 1024;
header_line  *header_last      = NULL;
header_line  *header_list      = NULL;
int     header_maxsize         = HEADER_MAXSIZE;
int     header_line_maxsize    = 0;

typedef struct {
  uschar *name;
  int     len;
  BOOL    allow_resent;
  int     htype;
} header_name;
header_name header_names[] = {
  { US"bcc",            3, TRUE,  htype_bcc },
  { US"cc",             2, TRUE,  htype_cc },
  { US"date",           4, TRUE,  htype_date },
  { US"delivery-date", 13, FALSE, htype_delivery_date },
  { US"envelope-to",   11, FALSE, htype_envelope_to },
  { US"from",           4, TRUE,  htype_from },
  { US"message-id",    10, TRUE,  htype_id },
  { US"received",       8, FALSE, htype_received },
  { US"reply-to",       8, FALSE, htype_reply_to },
  { US"return-path",   11, FALSE, htype_return_path },
  { US"sender",         6, TRUE,  htype_sender },
  { US"subject",        7, FALSE, htype_subject },
  { US"to",             2, TRUE,  htype_to }
};

int header_names_size          = sizeof(header_names)/sizeof(header_name);

BOOL    header_rewritten       = FALSE;
uschar *helo_accept_junk_hosts = NULL;
uschar *helo_allow_chars       = US"";
uschar *helo_lookup_domains    = US"@ : @[]";
uschar *helo_try_verify_hosts  = NULL;
BOOL    helo_verified          = FALSE;
BOOL    helo_verify_failed     = FALSE;
uschar *helo_verify_hosts      = NULL;
const uschar *hex_digits       = CUS"0123456789abcdef";
uschar *hold_domains           = NULL;
BOOL    host_checking          = FALSE;
BOOL    host_checking_callout  = FALSE;
uschar *host_data              = NULL;
BOOL    host_find_failed_syntax= FALSE;
uschar *host_lookup            = NULL;
BOOL    host_lookup_deferred   = FALSE;
BOOL    host_lookup_failed     = FALSE;
uschar *host_lookup_order      = US"bydns:byaddr";
uschar *host_lookup_msg        = US"";
int     host_number            = 0;
uschar *host_number_string     = NULL;
uschar *host_reject_connection = NULL;
tree_node *hostlist_anchor     = NULL;
int     hostlist_count         = 0;
uschar *hosts_treat_as_local   = NULL;
uschar *hosts_connection_nolog = NULL;

int     ignore_bounce_errors_after = 10*7*24*60*60;  /* 10 weeks */
BOOL    ignore_fromline_local  = FALSE;
uschar *ignore_fromline_hosts  = NULL;
BOOL    inetd_wait_mode        = FALSE;
int     inetd_wait_timeout     = -1;
uschar *interface_address      = NULL;
int     interface_port         = -1;
BOOL    is_inetd               = FALSE;
uschar *iterate_item           = NULL;

int     journal_fd             = -1;

int     keep_malformed         = 4*24*60*60;    /* 4 days */

uschar *eldap_dn               = NULL;
int     load_average           = -2;
BOOL    local_error_message    = FALSE;
BOOL    local_from_check       = TRUE;
uschar *local_from_prefix      = NULL;
uschar *local_from_suffix      = NULL;

#if HAVE_IPV6
uschar *local_interfaces       = US"<; ::0 ; 0.0.0.0";
#else
uschar *local_interfaces       = US"0.0.0.0";
#endif

uschar *local_scan_data        = NULL;
int     local_scan_timeout     = 5*60;
BOOL    local_sender_retain    = FALSE;
gid_t   local_user_gid         = (gid_t)(-1);
uid_t   local_user_uid         = (uid_t)(-1);

tree_node *localpartlist_anchor= NULL;
int     localpartlist_count    = 0;
uschar *log_buffer             = NULL;
unsigned int log_extra_selector = LX_default;
#define US   (unsigned char *)
uschar *log_file_path          = US LOG_FILE_PATH;
                           //"\0<--------------Space to patch log_file_path->";

/* Those log options with L_xxx identifiers have values less than 0x800000 and
are the ones that get put into log_write_selector. They can be used in calls to
log_write() to test for the bit. The options with LX_xxx identifiers have
values greater than 0x80000000 and are put into log_extra_selector (without the
top bit). They are never used in calls to log_write(), but are tested
independently. This separation became necessary when the number of log
selectors was getting close to filling a 32-bit word. */

/* Note that this list must be in alphabetical order. */

bit_table log_options[]        = {
  { US"acl_warn_skipped",             LX_acl_warn_skipped },
  { US"address_rewrite",              L_address_rewrite },
  { US"all",                          L_all },
  { US"all_parents",                  L_all_parents },
  { US"arguments",                    LX_arguments },
  { US"connection_reject",            L_connection_reject },
  { US"delay_delivery",               L_delay_delivery },
  { US"deliver_time",                 LX_deliver_time },
  { US"delivery_size",                LX_delivery_size },
  { US"dnslist_defer",                L_dnslist_defer },
  { US"etrn",                         L_etrn },
  { US"host_lookup_failed",           L_host_lookup_failed },
  { US"ident_timeout",                LX_ident_timeout },
  { US"incoming_interface",           LX_incoming_interface },
  { US"incoming_port",                LX_incoming_port },
  { US"lost_incoming_connection",     L_lost_incoming_connection },
  { US"outgoing_port",                LX_outgoing_port },
  { US"pid",                          LX_pid },
  { US"queue_run",                    L_queue_run },
  { US"queue_time",                   LX_queue_time },
  { US"queue_time_overall",           LX_queue_time_overall },
  { US"received_recipients",          LX_received_recipients },
  { US"received_sender",              LX_received_sender },
  { US"rejected_header",              LX_rejected_header },
  { US"rejected_headers",             LX_rejected_header },
  { US"retry_defer",                  L_retry_defer },
  { US"return_path_on_delivery",      LX_return_path_on_delivery },
  { US"sender_on_delivery",           LX_sender_on_delivery },
  { US"sender_verify_fail",           LX_sender_verify_fail },
  { US"size_reject",                  L_size_reject },
  { US"skip_delivery",                L_skip_delivery },
  { US"smtp_confirmation",            LX_smtp_confirmation },
  { US"smtp_connection",              L_smtp_connection },
  { US"smtp_incomplete_transaction",  L_smtp_incomplete_transaction },
  { US"smtp_no_mail",                 LX_smtp_no_mail },
  { US"smtp_protocol_error",          L_smtp_protocol_error },
  { US"smtp_syntax_error",            L_smtp_syntax_error },
  { US"subject",                      LX_subject },
  { US"tls_certificate_verified",     LX_tls_certificate_verified },
  { US"tls_cipher",                   LX_tls_cipher },
  { US"tls_peerdn",                   LX_tls_peerdn },
  { US"tls_sni",                      LX_tls_sni },
  { US"unknown_in_list",              LX_unknown_in_list }
};

int     log_options_count      = sizeof(log_options)/sizeof(bit_table);
int     log_reject_target      = 0;
uschar *log_selector_string    = NULL;
FILE   *log_stderr             = NULL;
BOOL    log_testing_mode       = FALSE;
BOOL    log_timezone           = FALSE;
unsigned int log_write_selector= L_default;
uschar *login_sender_address   = NULL;
int     lookup_open_max        = 25;
uschar *lookup_value           = NULL;

typedef struct macro_item {
  struct  macro_item *next;
  BOOL    command_line;
  uschar *replacement;
  uschar  name[1];
} macro_item;

macro_item  *macros            = NULL;
uschar *mailstore_basename     = NULL;
#ifdef WITH_CONTENT_SCAN
uschar *malware_name           = NULL;  /* Virus Name */
#endif
int     max_received_linelength= 0;
int     max_username_length    = 0;
int     message_age            = 0;
uschar *message_body           = NULL;
uschar *message_body_end       = NULL;
BOOL    message_body_newlines  = FALSE;
int     message_body_size      = 0;
int     message_body_visible   = 500;
int     message_ended          = END_NOTSTARTED;
uschar *message_headers        = NULL;
uschar *message_id;
uschar *message_id_domain      = NULL;
uschar *message_id_text        = NULL;
struct timeval message_id_tv   = { 0, 0 };
uschar  message_id_option[MESSAGE_ID_LENGTH + 3];
uschar *message_id_external;
int     message_linecount      = 0;
BOOL    message_logs           = TRUE;
int     message_size           = 0;
uschar *message_size_limit     = US"50M";
uschar  message_subdir[2]      = { 0, 0 };
uschar *message_reference      = NULL;

/* MIME ACL expandables */
#ifdef WITH_CONTENT_SCAN
int     mime_anomaly_level     = 0;
const uschar *mime_anomaly_text      = NULL;
uschar *mime_boundary          = NULL;
uschar *mime_charset           = NULL;
uschar *mime_content_description = NULL;
uschar *mime_content_disposition = NULL;
uschar *mime_content_id        = NULL;
unsigned int mime_content_size = 0;
uschar *mime_content_transfer_encoding = NULL;
uschar *mime_content_type      = NULL;
uschar *mime_decoded_filename  = NULL;
uschar *mime_filename          = NULL;
int     mime_is_multipart      = 0;
int     mime_is_coverletter    = 0;
int     mime_is_rfc822         = 0;
int     mime_part_count        = -1;
#endif

BOOL    mua_wrapper            = FALSE;

uid_t  *never_users            = NULL;
#ifdef WITH_CONTENT_SCAN
BOOL    no_mbox_unspool        = FALSE;
#endif
BOOL    no_multiline_responses = FALSE;

uid_t   original_euid;
gid_t   originator_gid;
uschar *originator_login       = NULL;
uschar *originator_name        = NULL;
uid_t   originator_uid;
uschar *override_local_interfaces = NULL;
uschar *override_pid_file_path = NULL;

BOOL    parse_allow_group      = FALSE;
BOOL    parse_found_group      = FALSE;
uschar *percent_hack_domains   = NULL;
uschar *pid_file_path          = US PID_FILE_PATH;
                           //"\0<--------------Space to patch pid_file_path->";
BOOL    pipelining_enable      = TRUE;
uschar *pipelining_advertise_hosts = US"*";
BOOL    preserve_message_logs  = FALSE;
uschar *primary_hostname       = NULL;
BOOL    print_topbitchars      = FALSE;
uschar  process_info[PROCESS_INFO_SIZE];
int     process_info_len       = 0;
uschar *process_log_path       = NULL;
BOOL    prod_requires_admin    = TRUE;
uschar *prvscheck_address      = NULL;
uschar *prvscheck_keynum       = NULL;
uschar *prvscheck_result       = NULL;


uschar *qualify_domain_recipient = NULL;
uschar *qualify_domain_sender  = NULL;
BOOL    queue_2stage           = FALSE;
uschar *queue_domains          = NULL;
int     queue_interval         = -1;
BOOL    queue_list_requires_admin = TRUE;
BOOL    queue_only             = FALSE;
uschar *queue_only_file        = NULL;
int     queue_only_load        = -1;
BOOL    queue_only_load_latch  = TRUE;
BOOL    queue_only_override    = TRUE;
BOOL    queue_only_policy      = FALSE;
BOOL    queue_run_first_delivery = FALSE;
BOOL    queue_run_force        = FALSE;
BOOL    queue_run_in_order     = FALSE;
BOOL    queue_run_local        = FALSE;
int     queue_run_max          = 5;
pid_t   queue_run_pid          = (pid_t)0;
int     queue_run_pipe         = -1;
BOOL    queue_running          = FALSE;
BOOL    queue_smtp             = FALSE;
uschar *queue_smtp_domains     = NULL;

unsigned int random_seed       = 0;
tree_node *ratelimiters_cmd    = NULL;
tree_node *ratelimiters_conn   = NULL;
tree_node *ratelimiters_mail   = NULL;
uschar *raw_active_hostname    = NULL;
uschar *raw_sender             = NULL;
uschar **raw_recipients        = NULL;
int     raw_recipients_count   = 0;

int     rcpt_count             = 0;
int     rcpt_fail_count        = 0;
int     rcpt_defer_count       = 0;
gid_t   real_gid;
uid_t   real_uid;
BOOL    really_exim            = TRUE;
BOOL    receive_call_bombout   = FALSE;
int     receive_linecount      = 0;
int     receive_messagecount   = 0;
int     receive_timeout        = 0;
int     received_count         = 0;
uschar *received_for           = NULL;

/*  This is the default text for Received headers generated by Exim. The
date  will be automatically added on the end. */

uschar *received_header_text   = US
     "Received: "
     "${if def:sender_rcvhost {from $sender_rcvhost\n\t}"
     "{${if def:sender_ident {from ${quote_local_part:$sender_ident} }}"
     "${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}"
     "by $primary_hostname "
     "${if def:received_protocol {with $received_protocol}} "
     #ifdef SUPPORT_TLS
     "${if def:tls_cipher {($tls_cipher)\n\t}}"
     #endif
     "(Exim $version_number)\n\t"
     "${if def:sender_address {(envelope-from <$sender_address>)\n\t}}"
     "id $message_exim_id"
     "${if def:received_for {\n\tfor $received_for}}"
     "\0<---------------Space to patch received_header_text->";

int     received_headers_max   = 30;
uschar *received_protocol      = NULL;
int     received_time          = 0;
uschar *recipient_data         = NULL;
uschar *recipient_unqualified_hosts = NULL;
uschar *recipient_verify_failure = NULL;
int     recipients_count       = 0;
BOOL    recipients_discarded   = FALSE;
recipient_item  *recipients_list = NULL;
int     recipients_list_max    = 0;
int     recipients_max         = 0;
BOOL    recipients_max_reject  = FALSE;
struct real_pcre;                 /* declaration; the definition is private  */
typedef struct real_pcre pcre;
const pcre *regex_AUTH         = NULL;
const pcre *regex_check_dns_names = NULL;
const pcre *regex_From         = NULL;
const pcre *regex_IGNOREQUOTA  = NULL;
const pcre *regex_PIPELINING   = NULL;
const pcre *regex_SIZE         = NULL;
const pcre *regex_smtp_code    = NULL;
const pcre *regex_ismsgid      = NULL;
#ifdef WHITELIST_D_MACROS
const pcre *regex_whitelisted_macro = NULL;
#endif
#ifdef WITH_CONTENT_SCAN
uschar *regex_match_string     = NULL;
#endif
int     remote_delivery_count  = 0;
int     remote_max_parallel    = 2;
uschar *remote_sort_domains    = NULL;
int     retry_data_expire      = 7*24*60*60;
int     retry_interval_max     = 24*60*60;
int     retry_maximum_timeout  = 0;        /* set from retry config */
typedef struct retry_rule {
  struct retry_rule *next;
  int    rule;
  int    timeout;
  int    p1;
  int    p2;
} retry_rule;
typedef struct retry_config {
  struct retry_config *next;
  uschar *pattern;
  int     basic_errno;
  int     more_errno;
  uschar *senders;
  retry_rule *rules;
} retry_config;
retry_config  *retries         = NULL;
uschar *return_path            = NULL;
BOOL    return_path_remove     = TRUE;
int     rewrite_existflags     = 0;
uschar *rfc1413_hosts          = US"*";
int     rfc1413_query_timeout  = 5;
/* BOOL    rfc821_domains         = FALSE;  <<< on the way out */
uid_t   root_gid               = ROOT_GID;
uid_t   root_uid               = ROOT_UID;

router_instance  *routers  = NULL;
router_instance  router_defaults = {
    NULL,                      /* chain pointer */
    NULL,                      /* name */
    NULL,                      /* info */
    NULL,                      /* private options block pointer */
    NULL,                      /* driver name */

    NULL,                      /* address_data */
#ifdef EXPERIMENTAL_BRIGHTMAIL
    NULL,                      /* bmi_rule */
#endif
    NULL,                      /* cannot_route_message */
    NULL,                      /* condition */
    NULL,                      /* current_directory */
    NULL,                      /* debug_string */
    NULL,                      /* domains */
    NULL,                      /* errors_to */
    NULL,                      /* expand_gid */
    NULL,                      /* expand_uid */
    NULL,                      /* expand_more */
    NULL,                      /* expand_unseen */
    NULL,                      /* extra_headers */
    NULL,                      /* fallback_hosts */
    NULL,                      /* home_directory */
    NULL,                      /* ignore_target_hosts */
    NULL,                      /* local_parts */
    NULL,                      /* pass_router_name */
    NULL,                      /* prefix */
    NULL,                      /* redirect_router_name */
    NULL,                      /* remove_headers */
    NULL,                      /* require_files */
    NULL,                      /* router_home_directory */
    US"freeze",                /* self */
    NULL,                      /* senders */
    NULL,                      /* suffix */
    NULL,                      /* translate_ip_address */
    NULL,                      /* transport_name */

    TRUE,                      /* address_test */
#ifdef EXPERIMENTAL_BRIGHTMAIL
    FALSE,                     /* bmi_deliver_alternate */
    FALSE,                     /* bmi_deliver_default */
    FALSE,                     /* bmi_dont_deliver */
#endif
    TRUE,                      /* expn */
    FALSE,                     /* caseful_local_part */
    FALSE,                     /* check_local_user */
    FALSE,                     /* disable_logging */
    FALSE,                     /* fail_verify_recipient */
    FALSE,                     /* fail_verify_sender */
    FALSE,                     /* gid_set */
    FALSE,                     /* initgroups */
    TRUE_UNSET,                /* log_as_local */
    TRUE,                      /* more */
    FALSE,                     /* pass_on_timeout */
    FALSE,                     /* prefix_optional */
    TRUE,                      /* repeat_use */
    TRUE_UNSET,                /* retry_use_local_part - fudge "unset" */
    FALSE,                     /* same_domain_copy_routing */
    FALSE,                     /* self_rewrite */
    FALSE,                     /* suffix_optional */
    FALSE,                     /* verify_only */
    TRUE,                      /* verify_recipient */
    TRUE,                      /* verify_sender */
    FALSE,                     /* uid_set */
    FALSE,                     /* unseen */

    self_freeze,               /* self_code */
    (uid_t)(-1),               /* uid */
    (gid_t)(-1),               /* gid */

    NULL,                      /* fallback_hostlist */
    NULL,                      /* transport instance */
    NULL,                      /* pass_router */
    NULL                       /* redirect_router */
};

typedef struct ip_address_item {
  struct ip_address_item *next;
  int    port;
  BOOL   v6_include_v4;            /* Used in the daemon */
  uschar address[46];
} ip_address_item;
ip_address_item *running_interfaces = NULL;
BOOL    running_in_test_harness = FALSE;

/* This is a weird one. The following string gets patched in the binary by the
script that sets up a copy of Exim for running in the test harness. It seems
that compilers are now clever, and share constant strings if they can.
Elsewhere in Exim the string "<" is used. The compiler optimization seems to
make use of the end of this string in order to save space. So the patching then
wrecks this. We defeat this optimization by adding some additional characters
onto the end of the string. */

uschar *running_status         = US">>>running<<<" "\0EXTRA";

int     runrc                  = 0;

uschar *search_error_message   = NULL;
BOOL    search_find_defer      = FALSE;
uschar *self_hostname          = NULL;
uschar *sender_address         = NULL;
unsigned int sender_address_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_address_data    = NULL;
BOOL    sender_address_forced  = FALSE;
uschar *sender_address_unrewritten = NULL;
uschar *sender_data            = NULL;
unsigned int sender_domain_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_fullhost        = NULL;
uschar *sender_helo_name       = NULL;
uschar **sender_host_aliases   = &no_aliases;
uschar *sender_host_address    = NULL;
uschar *sender_host_authenticated = NULL;
unsigned int sender_host_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_host_name       = NULL;
int     sender_host_port       = 0;
BOOL    sender_host_notsocket  = FALSE;
BOOL    sender_host_unknown    = FALSE;
uschar *sender_ident           = NULL;
BOOL    sender_local           = FALSE;
BOOL    sender_name_forced     = FALSE;
uschar *sender_rate            = NULL;
uschar *sender_rate_limit      = NULL;
uschar *sender_rate_period     = NULL;
uschar *sender_rcvhost         = NULL;
BOOL    sender_set_untrusted   = FALSE;
uschar *sender_unqualified_hosts = NULL;
uschar *sender_verify_failure = NULL;
address_item *sender_verified_list  = NULL;
address_item *sender_verified_failed = NULL;
int     sender_verified_rc     = -1;
BOOL    sender_verified_responded = FALSE;
uschar *sending_ip_address     = NULL;
int     sending_port           = -1;
typedef volatile int SIGNAL_BOOL;
SIGNAL_BOOL sigalrm_seen       = FALSE;
uschar **sighup_argv           = NULL;
int     smtp_accept_count      = 0;
BOOL    smtp_accept_keepalive  = TRUE;
int     smtp_accept_max        = 20;
int     smtp_accept_max_nonmail= 10;
uschar *smtp_accept_max_nonmail_hosts = US"*";
int     smtp_accept_max_per_connection = 1000;
uschar *smtp_accept_max_per_host = NULL;
int     smtp_accept_queue      = 0;
int     smtp_accept_queue_per_connection = 10;
int     smtp_accept_reserve    = 0;
uschar *smtp_active_hostname   = NULL;
BOOL    smtp_authenticated     = FALSE;
uschar *smtp_banner            = US"$smtp_active_hostname ESMTP "
                             "Exim $version_number $tod_full"
                             "\0<---------------Space to patch smtp_banner->";
BOOL    smtp_batched_input     = FALSE;
BOOL    smtp_check_spool_space = TRUE;
int     smtp_ch_index          = 0;
uschar *smtp_cmd_argument      = NULL;
uschar *smtp_cmd_buffer        = NULL;
time_t  smtp_connection_start  = 0;
uschar  smtp_connection_had[SMTP_HBUFF_SIZE];
int     smtp_connect_backlog   = 20;
double  smtp_delay_mail        = 0.0;
double  smtp_delay_rcpt        = 0.0;
BOOL    smtp_enforce_sync      = TRUE;
FILE   *smtp_in                = NULL;
BOOL    smtp_input             = FALSE;
int     smtp_load_reserve      = -1;
int     smtp_mailcmd_count     = 0;
FILE   *smtp_out               = NULL;
uschar *smtp_etrn_command      = NULL;
BOOL    smtp_etrn_serialize    = TRUE;
int     smtp_max_synprot_errors= 3;
int     smtp_max_unknown_commands = 3;
uschar *smtp_notquit_reason    = NULL;
uschar *smtp_ratelimit_hosts   = NULL;
uschar *smtp_ratelimit_mail    = NULL;
uschar *smtp_ratelimit_rcpt    = NULL;
uschar *smtp_read_error        = US"";
int     smtp_receive_timeout   = 5*60;
uschar *smtp_reserve_hosts     = NULL;
BOOL    smtp_return_error_details = FALSE;
int     smtp_rlm_base          = 0;
double  smtp_rlm_factor        = 0.0;
int     smtp_rlm_limit         = 0;
int     smtp_rlm_threshold     = INT_MAX;
int     smtp_rlr_base          = 0;
double  smtp_rlr_factor        = 0.0;
int     smtp_rlr_limit         = 0;
int     smtp_rlr_threshold     = INT_MAX;
BOOL    smtp_use_pipelining    = FALSE;
BOOL    smtp_use_size          = FALSE;

#ifdef WITH_CONTENT_SCAN
uschar *spamd_address          = US"127.0.0.1 783";
uschar *spam_bar               = NULL;
uschar *spam_report            = NULL;
uschar *spam_score             = NULL;
uschar *spam_score_int         = NULL;
#endif
#ifdef EXPERIMENTAL_SPF
uschar *spf_guess              = US"v=spf1 a/24 mx/24 ptr ?all";
uschar *spf_header_comment     = NULL;
uschar *spf_received           = NULL;
uschar *spf_result             = NULL;
uschar *spf_smtp_comment       = NULL;
#endif

BOOL    split_spool_directory  = FALSE;
uschar *spool_directory        = US SPOOL_DIRECTORY
                           "\0<--------------Space to patch spool_directory->";
#ifdef EXPERIMENTAL_SRS
uschar *srs_config             = NULL;
uschar *srs_db_address         = NULL;
uschar *srs_db_key             = NULL;
int     srs_hashlength         = 6;
int     srs_hashmin            = -1;
int     srs_maxage             = 31;
uschar *srs_orig_recipient     = NULL;
uschar *srs_orig_sender        = NULL;
uschar *srs_recipient          = NULL;
uschar *srs_secrets            = NULL;
uschar *srs_status             = NULL;
BOOL    srs_usehash            = TRUE;
BOOL    srs_usetimestamp       = TRUE;
#endif
BOOL    strict_acl_vars        = FALSE;
int     string_datestamp_offset= -1;
int     string_datestamp_length= 0;
int     string_datestamp_type  = -1;
BOOL    strip_excess_angle_brackets = FALSE;
BOOL    strip_trailing_dot     = FALSE;
uschar *submission_domain      = NULL;
BOOL    submission_mode        = FALSE;
uschar *submission_name        = NULL;
BOOL    suppress_local_fixups  = FALSE;
BOOL    synchronous_delivery   = FALSE;
BOOL    syslog_duplication     = TRUE;
int     syslog_facility        = LOG_MAIL;
uschar *syslog_processname     = US"exim";
BOOL    syslog_timestamp       = TRUE;
uschar *system_filter          = NULL;

uschar *system_filter_directory_transport = NULL;
uschar *system_filter_file_transport = NULL;
uschar *system_filter_pipe_transport = NULL;
uschar *system_filter_reply_transport = NULL;

gid_t   system_filter_gid      = 0;
BOOL    system_filter_gid_set  = FALSE;
uid_t   system_filter_uid      = (uid_t)-1;
BOOL    system_filter_uid_set  = FALSE;
BOOL    system_filtering       = FALSE;

BOOL    tcp_nodelay            = TRUE;
#ifdef USE_TCP_WRAPPERS
uschar *tcp_wrappers_daemon_name = US TCP_WRAPPERS_DAEMON_NAME;
#endif
int     test_harness_load_avg  = 0;
int     thismessage_size_limit = 0;
int     timeout_frozen_after   = 0;
BOOL    timestamps_utc         = FALSE;

transport_instance  *transports = NULL;

transport_instance  transport_defaults = {
    NULL,                     /* chain pointer */
    NULL,                     /* name */
    NULL,                     /* info */
    NULL,                     /* private options block pointer */
    NULL,                     /* driver name */
    NULL,                     /* setup entry point */
    1,                        /* batch_max */
    NULL,                     /* batch_id */
    NULL,                     /* home_dir */
    NULL,                     /* current_dir */
    TRUE,                     /* multi-domain */
    FALSE,                    /* overrides_hosts */
    100,                      /* max_addresses */
    500,                      /* connection_max_messages */
    FALSE,                    /* deliver_as_creator */
    FALSE,                    /* disable_logging */
    FALSE,                    /* initgroups */
    FALSE,                    /* uid_set */
    FALSE,                    /* gid_set */
    (uid_t)(-1),              /* uid */
    (gid_t)(-1),              /* gid */
    NULL,                     /* expand_uid */
    NULL,                     /* expand_gid */
    NULL,                     /* warn_message */
    NULL,                     /* shadow */
    NULL,                     /* shadow_condition */
    NULL,                     /* filter_command */
    NULL,                     /* add_headers */
    NULL,                     /* remove_headers */
    NULL,                     /* return_path */
    NULL,                     /* debug_string */
    NULL,                     /* message_size_limit */
    NULL,                     /* headers_rewrite */
    NULL,                     /* rewrite_rules */
    0,                        /* rewrite_existflags */
    300,                      /* filter_timeout */
    FALSE,                    /* body_only */
    FALSE,                    /* delivery_date_add */
    FALSE,                    /* envelope_to_add */
    FALSE,                    /* headers_only */
    FALSE,                    /* rcpt_include_affixes */
    FALSE,                    /* return_path_add */
    FALSE,                    /* return_output */
    FALSE,                    /* return_fail_output */
    FALSE,                    /* log_output */
    FALSE,                    /* log_fail_output */
    FALSE,                    /* log_defer_output */
    TRUE_UNSET                /* retry_use_local_part: BOOL, but set neither
                                 1 nor 0 so can detect unset */
};

int     transport_count;
int     transport_newlines;
uschar **transport_filter_argv  = NULL;
int     transport_filter_timeout;
BOOL    transport_filter_timed_out = FALSE;
int     transport_write_timeout= 0;

tree_node  *tree_dns_fails     = NULL;
tree_node  *tree_duplicates    = NULL;
tree_node  *tree_nonrecipients = NULL;
tree_node  *tree_unusable      = NULL;

BOOL    trusted_caller         = FALSE;
BOOL    trusted_config         = TRUE;
gid_t  *trusted_groups         = NULL;
uid_t  *trusted_users          = NULL;
uschar *timezone_string        = US TIMEZONE_DEFAULT;

uschar *unknown_login          = NULL;
uschar *unknown_username       = NULL;
uschar *untrusted_set_sender   = NULL;

/*  A regex for matching a "From_" line in an incoming message, in the form

    From ph10 Fri Jan  5 12:35 GMT 1996

which  the "mail" commands send to the MTA (undocumented, of course), or in
the  form

    From ph10 Fri, 7 Jan 97 14:00:00 GMT

which  is apparently used by some UUCPs, despite it not being in RFC 976.
Because  of variations in time formats, just match up to the minutes. That
should  be sufficient. Examples have been seen of time fields like 12:1:03,
so  just require one digit for hours and minutes. The weekday is also absent
in  some forms. */

uschar *uucp_from_pattern      = US
   "^From\\s+(\\S+)\\s+(?:[a-zA-Z]{3},?\\s+)?"    /* Common start */
   "(?:"                                          /* Non-extracting bracket */
   "[a-zA-Z]{3}\\s+\\d?\\d|"                      /* First form */
   "\\d?\\d\\s+[a-zA-Z]{3}\\s+\\d\\d(?:\\d\\d)?"  /* Second form */
   ")"                                            /* End alternation */
   "\\s+\\d\\d?:\\d\\d?";                         /* Start of time */

uschar *uucp_from_sender       = US"$1";

uschar *warn_message_file      = NULL;
uschar *warnmsg_delay          = NULL;
uschar *warnmsg_recipients     = NULL;
BOOL    write_rejectlog        = TRUE;

uschar *version_copyright      =
 US"Copyright (c) University of Cambridge, 1995 - 2012\n"
   "(c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2012";
uschar *version_date           = US"?";
uschar *version_cnumber        = US"????";
uschar *version_string         = US"?";

int     warning_count          = 0;
/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Phil Pennock 2012 */

/* This file provides TLS/SSL support for Exim using the GnuTLS library,
one of the available supported implementations.  This file is #included into
tls.c when USE_GNUTLS has been set.

The code herein is a revamp of GnuTLS integration using the current APIs; the
original tls-gnu.c was based on a patch which was contributed by Nikos
Mavroyanopoulos.  The revamp is partially a rewrite, partially cut&paste as
appropriate.

APIs current as of GnuTLS 2.12.18; note that the GnuTLS manual is for GnuTLS 3,
which is not widely deployed by OS vendors.  Will note issues below, which may
assist in updating the code in the future.  Another sources of hints is
mod_gnutls for Apache (SNI callback registration and handling).

Keeping client and server variables more split than before and is currently
the norm, in anticipation of TLS in ACL callouts.

I wanted to switch to gnutls_certificate_set_verify_function() so that
certificate rejection could happen during handshake where it belongs, rather
than being dropped afterwards, but that was introduced in 2.10.0 and Debian
(6.0.5) is still on 2.8.6.  So for now we have to stick with sub-par behaviour.

(I wasn't looking for libraries quite that old, when updating to get rid of
compiler warnings of deprecated APIs.  If it turns out that a lot of the rest
require current GnuTLS, then we'll drop support for the ancient libraries).
*/

#include <gnutls/gnutls.h>
/* needed for cert checks in verification and DN extraction: */
#include <gnutls/x509.h>
/* man-page is incorrect, gnutls_rnd() is not in gnutls.h: */
#include <gnutls/crypto.h>

/* GnuTLS 2 vs 3

GnuTLS 3 only:
  gnutls_global_set_audit_log_function()

Changes:
  gnutls_certificate_verify_peers2(): is new, drop the 2 for old version
*/

/* Local static variables for GnuTLS */

/* Values for verify_requirement */

enum peer_verify_requirement { VERIFY_NONE, VERIFY_OPTIONAL, VERIFY_REQUIRED };

/* This holds most state for server or client; with this, we can set up an
outbound TLS-enabled connection in an ACL callout, while not stomping all
over the TLS variables available for expansion.

Some of these correspond to variables in globals.c; those variables will
be set to point to content in one of these instances, as appropriate for
the stage of the process lifetime.

Not handled here: globals tls_active, tls_bits, tls_cipher, tls_peerdn,
tls_certificate_verified, tls_channelbinding_b64, tls_sni.
*/

typedef struct exim_gnutls_state {
  gnutls_session_t session;
  gnutls_certificate_credentials_t x509_cred;
  gnutls_priority_t priority_cache;
  enum peer_verify_requirement verify_requirement;
  int fd_in;
  int fd_out;
  BOOL peer_cert_verified;
  BOOL trigger_sni_changes;
  BOOL have_set_peerdn;
  const struct host_item *host;
  uschar *peerdn;
  uschar *ciphersuite;
  uschar *received_sni;

  const uschar *tls_certificate;
  const uschar *tls_privatekey;
  const uschar *tls_sni; /* client send only, not received */
  const uschar *tls_verify_certificates;
  const uschar *tls_crl;
  const uschar *tls_require_ciphers;
  uschar *exp_tls_certificate;
  uschar *exp_tls_privatekey;
  uschar *exp_tls_sni;
  uschar *exp_tls_verify_certificates;
  uschar *exp_tls_crl;
  uschar *exp_tls_require_ciphers;

  uschar *xfer_buffer;
  int xfer_buffer_lwm;
  int xfer_buffer_hwm;
  int xfer_eof;
  int xfer_error;
} exim_gnutls_state_st;

static const exim_gnutls_state_st exim_gnutls_state_init = {
  NULL, NULL, NULL, VERIFY_NONE, -1, -1, FALSE, FALSE, FALSE,
  NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, 0, 0, 0, 0,
};

/* Not only do we have our own APIs which don't pass around state, assuming
it's held in globals, GnuTLS doesn't appear to let us register callback data
for callbacks, or as part of the session, so we have to keep a "this is the
context we're currently dealing with" pointer and rely upon being
single-threaded to keep from processing data on an inbound TLS connection while
talking to another TLS connection for an outbound check.  This does mean that
there's no way for heart-beats to be responded to, for the duration of the
second connection. */

static exim_gnutls_state_st state_server, state_client;
static exim_gnutls_state_st *current_global_tls_state;

/* dh_params are initialised once within the lifetime of a process using TLS;
if we used TLS in a long-lived daemon, we'd have to reconsider this.  But we
don't want to repeat this. */

static gnutls_dh_params_t dh_server_params = NULL;

/* No idea how this value was chosen; preserving it.  Default is 3600. */

static const int ssl_session_timeout = 200;

static const char * const exim_default_gnutls_priority = "NORMAL";

/* Guard library core initialisation */

static BOOL exim_gnutls_base_init_done = FALSE;


/* ------------------------------------------------------------------------ */
/* macros */

#define MAX_HOST_LEN 255

/* Set this to control gnutls_global_set_log_level(); values 0 to 9 will setup
the library logging; a value less than 0 disables the calls to set up logging
callbacks. */
#ifndef EXIM_GNUTLS_LIBRARY_LOG_LEVEL
#define EXIM_GNUTLS_LIBRARY_LOG_LEVEL -1
#endif

#ifndef EXIM_CLIENT_DH_MIN_BITS
#define EXIM_CLIENT_DH_MIN_BITS 1024
#endif

/* With GnuTLS 2.12.x+ we have gnutls_sec_param_to_pk_bits() with which we
can ask for a bit-strength.  Without that, we stick to the constant we had
before, for now. */
#ifndef EXIM_SERVER_DH_BITS_PRE2_12
#define EXIM_SERVER_DH_BITS_PRE2_12 1024
#endif

#define exim_gnutls_err_check(Label) do { \
  if (rc != GNUTLS_E_SUCCESS) { return tls_error((Label), gnutls_strerror(rc), host); } } while (0)

#define expand_check_tlsvar(Varname) expand_check(state->Varname, US #Varname, &state->exp_##Varname)

#if GNUTLS_VERSION_NUMBER >= 0x020c00
#define HAVE_GNUTLS_SESSION_CHANNEL_BINDING
#define HAVE_GNUTLS_SEC_PARAM_CONSTANTS
#define HAVE_GNUTLS_RND
#endif




/* ------------------------------------------------------------------------ */
/* Callback declarations */

#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
static void exim_gnutls_logger_cb(int level, const char *message);
#endif

static int exim_sni_handling_cb(gnutls_session_t session);




/* ------------------------------------------------------------------------ */
/* Static functions */

/*************************************************
*               Handle TLS error                 *
*************************************************/

/* Called from lots of places when errors occur before actually starting to do
the TLS handshake, that is, while the session is still in clear. Always returns
DEFER for a server and FAIL for a client so that most calls can use "return
tls_error(...)" to do this processing and then give an appropriate return. A
single function is used for both server and client, because it is called from
some shared functions.

Argument:
  prefix    text to include in the logged error
  msg       additional error string (may be NULL)
            usually obtained from gnutls_strerror()
  host      NULL if setting up a server;
            the connected host if setting up a client

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(const uschar *prefix, const char *msg, const host_item *host)
{
if (host)
  {
  log_write(0, LOG_MAIN, "TLS error on connection to %s [%s] (%s)%s%s",
      host->name, host->address, prefix, msg ? ": " : "", msg ? msg : "");
  return FAIL;
  }
else
  {
  uschar *conn_info = smtp_get_connection_info();
  if (Ustrncmp(conn_info, US"SMTP ", 5) == 0)
    conn_info += 5;
  log_write(0, LOG_MAIN, "TLS error on %s (%s)%s%s",
      conn_info, prefix, msg ? ": " : "", msg ? msg : "");
  return DEFER;
  }
}




/*************************************************
*    Deal with logging errors during I/O         *
*************************************************/

/* We have to get the identity of the peer from saved data.

Argument:
  state    the current GnuTLS exim state container
  rc       the GnuTLS error code, or 0 if it's a local error
  when     text identifying read or write
  text     local error text when ec is 0

Returns:   nothing
*/

static void
record_io_error(exim_gnutls_state_st *state, int rc, uschar *when, uschar *text)
{
const char *msg;

if (rc == GNUTLS_E_FATAL_ALERT_RECEIVED)
  msg = CS string_sprintf("%s: %s", US gnutls_strerror(rc),
    US gnutls_alert_get_name(gnutls_alert_get(state->session)));
else
  msg = gnutls_strerror(rc);

tls_error(when, msg, state->host);
}




/*************************************************
*        Set various Exim expansion vars         *
*************************************************/

/* We set various Exim global variables from the state, once a session has
been established.  With TLS callouts, may need to change this to stack
variables, or just re-call it with the server state after client callout
has finished.

Make sure anything set here is inset in tls_getc().

Sets:
  tls_active                fd
  tls_bits                  strength indicator
  tls_certificate_verified  bool indicator
  tls_channelbinding_b64    for some SASL mechanisms
  tls_cipher                a string
  tls_peerdn                a string
  tls_sni                   a (UTF-8) string
Also:
  current_global_tls_state  for API limitations

Argument:
  state      the relevant exim_gnutls_state_st *
*/

static void
extract_exim_vars_from_tls_state(exim_gnutls_state_st *state)
{
gnutls_cipher_algorithm_t cipher;
#ifdef HAVE_GNUTLS_SESSION_CHANNEL_BINDING
int old_pool;
int rc;
gnutls_datum_t channel;
#endif

current_global_tls_state = state;

tls_active = state->fd_out;

cipher = gnutls_cipher_get(state->session);
/* returns size in "bytes" */
tls_bits = gnutls_cipher_get_key_size(cipher) * 8;

tls_cipher = state->ciphersuite;

DEBUG(D_tls) debug_printf("cipher: %s\n", tls_cipher);

tls_certificate_verified = state->peer_cert_verified;

/* note that tls_channelbinding_b64 is not saved to the spool file, since it's
only available for use for authenticators while this TLS session is running. */

uschar *tls_channelbinding_b64 = NULL;
tls_channelbinding_b64 = NULL;
#ifdef HAVE_GNUTLS_SESSION_CHANNEL_BINDING
channel.data = NULL;
channel.size = 0;
rc = gnutls_session_channel_binding(state->session, GNUTLS_CB_TLS_UNIQUE, &channel);
if (rc) {
  DEBUG(D_tls) debug_printf("Channel binding error: %s\n", gnutls_strerror(rc));
} else {
  old_pool = store_pool;
  store_pool = POOL_PERM;
  tls_channelbinding_b64 = auth_b64encode(channel.data, (int)channel.size);
  store_pool = old_pool;
  DEBUG(D_tls) debug_printf("Have channel bindings cached for possible auth usage.\n");
}
#endif

tls_peerdn = state->peerdn;

uschar *tls_sni                = NULL;
tls_sni = state->received_sni;
}




/*************************************************
*            Setup up DH parameters              *
*************************************************/

/* Generating the D-H parameters may take a long time. They only need to
be re-generated every so often, depending on security policy. What we do is to
keep these parameters in a file in the spool directory. If the file does not
exist, we generate them. This means that it is easy to cause a regeneration.

The new file is written as a temporary file and renamed, so that an incomplete
file is never present. If two processes both compute some new parameters, you
waste a bit of effort, but it doesn't seem worth messing around with locking to
prevent this.

Returns:     OK/DEFER/FAIL
*/

static int
init_server_dh(void)
{
int fd, rc;
unsigned int dh_bits;
gnutls_datum m;
uschar filename_buf[PATH_MAX];
uschar *filename = NULL;
size_t sz;
uschar *exp_tls_dhparam;
BOOL use_file_in_spool = FALSE;
BOOL use_fixed_file = FALSE;
host_item *host = NULL; /* dummy for macros */

DEBUG(D_tls) debug_printf("Initialising GnuTLS server params.\n");

rc = gnutls_dh_params_init(&dh_server_params);
exim_gnutls_err_check(US"gnutls_dh_params_init");

m.data = NULL;
m.size = 0;

uschar *tls_dhparam            = NULL;
if (!expand_check(tls_dhparam, US"tls_dhparam", &exp_tls_dhparam))
  return DEFER;

if (!exp_tls_dhparam)
  {
  DEBUG(D_tls) debug_printf("Loading default hard-coded DH params\n");
  m.data = US std_dh_prime_default();
  m.size = Ustrlen(m.data);
  }
else if (Ustrcmp(exp_tls_dhparam, "historic") == 0)
  use_file_in_spool = TRUE;
else if (Ustrcmp(exp_tls_dhparam, "none") == 0)
  {
  DEBUG(D_tls) debug_printf("Requested no DH parameters.\n");
  return OK;
  }
else if (exp_tls_dhparam[0] != '/')
  {
  m.data = US std_dh_prime_named(exp_tls_dhparam);
  if (m.data == NULL)
    return tls_error(US"No standard prime named", CS exp_tls_dhparam, NULL);
  m.size = Ustrlen(m.data);
  }
else
  {
  use_fixed_file = TRUE;
  filename = exp_tls_dhparam;
  }

if (m.data)
  {
  rc = gnutls_dh_params_import_pkcs3(dh_server_params, &m, GNUTLS_X509_FMT_PEM);
  exim_gnutls_err_check(US"gnutls_dh_params_import_pkcs3");
  DEBUG(D_tls) debug_printf("Loaded fixed standard D-H parameters\n");
  return OK;
  }

#ifdef HAVE_GNUTLS_SEC_PARAM_CONSTANTS
/* If you change this constant, also change dh_param_fn_ext so that we can use a
different filename and ensure we have sufficient bits. */
dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_NORMAL);
if (!dh_bits)
  return tls_error(US"gnutls_sec_param_to_pk_bits() failed", NULL, NULL);
DEBUG(D_tls)
  debug_printf("GnuTLS tells us that for D-H PK, NORMAL is %d bits.\n",
      dh_bits);
#else
dh_bits = EXIM_SERVER_DH_BITS_PRE2_12;
DEBUG(D_tls)
  debug_printf("GnuTLS lacks gnutls_sec_param_to_pk_bits(), using %d bits.\n",
      dh_bits);
#endif

/* Some clients have hard-coded limits. */
if (dh_bits > tls_dh_max_bits)
  {
  DEBUG(D_tls)
    debug_printf("tls_dh_max_bits clamping override, using %d bits instead.\n",
        tls_dh_max_bits);
  dh_bits = tls_dh_max_bits;
  }

if (use_file_in_spool)
  {
  if (!string_format(filename_buf, sizeof(filename_buf),
        "%s/gnutls-params-%d", spool_directory, dh_bits))
    return tls_error(US"overlong filename", NULL, NULL);
  filename = filename_buf;
  }

/* Open the cache file for reading and if successful, read it and set up the
parameters. */

fd = Uopen(filename, O_RDONLY, 0);
if (fd >= 0)
  {
  struct stat statbuf;
  FILE *fp;
  int saved_errno;

  if (fstat(fd, &statbuf) < 0)  /* EIO */
    {
    saved_errno = errno;
    (void)close(fd);
    return tls_error(US"TLS cache stat failed", strerror(saved_errno), NULL);
    }
  if (!S_ISREG(statbuf.st_mode))
    {
    (void)close(fd);
    return tls_error(US"TLS cache not a file", NULL, NULL);
    }
  fp = fdopen(fd, "rb");
  if (!fp)
    {
    saved_errno = errno;
    (void)close(fd);
    return tls_error(US"fdopen(TLS cache stat fd) failed",
        strerror(saved_errno), NULL);
    }

  m.size = statbuf.st_size;
  m.data = malloc(m.size);
  if (m.data == NULL)
    {
    fclose(fp);
    return tls_error(US"malloc failed", strerror(errno), NULL);
    }
  sz = fread(m.data, m.size, 1, fp);
  if (!sz)
    {
    saved_errno = errno;
    fclose(fp);
    free(m.data);
    return tls_error(US"fread failed", strerror(saved_errno), NULL);
    }
  fclose(fp);

  rc = gnutls_dh_params_import_pkcs3(dh_server_params, &m, GNUTLS_X509_FMT_PEM);
  free(m.data);
  exim_gnutls_err_check(US"gnutls_dh_params_import_pkcs3");
  DEBUG(D_tls) debug_printf("read D-H parameters from file \"%s\"\n", filename);
  }

/* If the file does not exist, fall through to compute new data and cache it.
If there was any other opening error, it is serious. */

else if (errno == ENOENT)
  {
  rc = -1;
  DEBUG(D_tls)
    debug_printf("D-H parameter cache file \"%s\" does not exist\n", filename);
  }
else
  return tls_error(string_open_failed(errno, "\"%s\" for reading", filename),
      NULL, NULL);

/* If ret < 0, either the cache file does not exist, or the data it contains
is not useful. One particular case of this is when upgrading from an older
release of Exim in which the data was stored in a different format. We don't
try to be clever and support both formats; we just regenerate new data in this
case. */

if (rc < 0)
  {
  uschar *temp_fn;
  unsigned int dh_bits_gen = dh_bits;

  if ((PATH_MAX - Ustrlen(filename)) < 10)
    return tls_error(US"Filename too long to generate replacement",
        CS filename, NULL);

  temp_fn = string_copy(US "%s.XXXXXXX");
  fd = mkstemp(CS temp_fn); /* modifies temp_fn */
  if (fd < 0)
    return tls_error(US"Unable to open temp file", strerror(errno), NULL);
  (void)fchown(fd, exim_uid, exim_gid);   /* Probably not necessary */

  /* GnuTLS overshoots!
   * If we ask for 2236, we might get 2237 or more.
   * But there's no way to ask GnuTLS how many bits there really are.
   * We can ask how many bits were used in a TLS session, but that's it!
   * The prime itself is hidden behind too much abstraction.
   * So we ask for less, and proceed on a wing and a prayer.
   * First attempt, subtracted 3 for 2233 and got 2240.
   */
  if (dh_bits >= EXIM_CLIENT_DH_MIN_BITS + 10)
    {
    dh_bits_gen = dh_bits - 10;
    DEBUG(D_tls)
      debug_printf("being paranoid about DH generation, make it '%d' bits'\n",
          dh_bits_gen);
    }

  DEBUG(D_tls)
    debug_printf("requesting generation of %d bit Diffie-Hellman prime ...\n",
        dh_bits_gen);
  rc = gnutls_dh_params_generate2(dh_server_params, dh_bits_gen);
  exim_gnutls_err_check(US"gnutls_dh_params_generate2");

  /* gnutls_dh_params_export_pkcs3() will tell us the exact size, every time,
  and I confirmed that a NULL call to get the size first is how the GnuTLS
  sample apps handle this. */

  sz = 0;
  m.data = NULL;
  rc = gnutls_dh_params_export_pkcs3(dh_server_params, GNUTLS_X509_FMT_PEM,
      m.data, &sz);
  if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
    exim_gnutls_err_check(US"gnutls_dh_params_export_pkcs3(NULL) sizing");
  m.size = sz;
  m.data = malloc(m.size);
  if (m.data == NULL)
    return tls_error(US"memory allocation failed", strerror(errno), NULL);
  /* this will return a size 1 less than the allocation size above */
  rc = gnutls_dh_params_export_pkcs3(dh_server_params, GNUTLS_X509_FMT_PEM,
      m.data, &sz);
  if (rc != GNUTLS_E_SUCCESS)
    {
    free(m.data);
    exim_gnutls_err_check(US"gnutls_dh_params_export_pkcs3() real");
    }
  m.size = sz; /* shrink by 1, probably */

  sz = write_to_fd_buf(fd, m.data, (size_t) m.size);
  if (sz != m.size)
    {
    free(m.data);
    return tls_error(US"TLS cache write D-H params failed",
        strerror(errno), NULL);
    }
  free(m.data);
  sz = write_to_fd_buf(fd, US"\n", 1);
  if (sz != 1)
    return tls_error(US"TLS cache write D-H params final newline failed",
        strerror(errno), NULL);

  rc = close(fd);
  if (rc)
    return tls_error(US"TLS cache write close() failed",
        strerror(errno), NULL);

  if (Urename(temp_fn, filename) < 0)
    return tls_error(string_sprintf("failed to rename \"%s\" as \"%s\"",
          temp_fn, filename), strerror(errno), NULL);

  DEBUG(D_tls) debug_printf("wrote D-H parameters to file \"%s\"\n", filename);
  }

DEBUG(D_tls) debug_printf("initialized server D-H parameters\n");
return OK;
}




/*************************************************
*       Variables re-expanded post-SNI           *
*************************************************/

/* Called from both server and client code, via tls_init(), and also from
the SNI callback after receiving an SNI, if tls_certificate includes "tls_sni".

We can tell the two apart by state->received_sni being non-NULL in callback.

The callback should not call us unless state->trigger_sni_changes is true,
which we are responsible for setting on the first pass through.

Arguments:
  state           exim_gnutls_state_st *

Returns:          OK/DEFER/FAIL
*/

static int
tls_expand_session_files(exim_gnutls_state_st *state)
{
struct stat statbuf;
int rc;
const host_item *host = state->host;  /* macro should be reconsidered? */
uschar *saved_tls_certificate = NULL;
uschar *saved_tls_privatekey = NULL;
uschar *saved_tls_verify_certificates = NULL;
uschar *saved_tls_crl = NULL;
int cert_count;

/* We check for tls_sni *before* expansion. */
if (!state->host)
  {
  if (!state->received_sni)
    {
    if (state->tls_certificate && Ustrstr(state->tls_certificate, US"tls_sni"))
      {
      DEBUG(D_tls) debug_printf("We will re-expand TLS session files if we receive SNI.\n");
      state->trigger_sni_changes = TRUE;
      }
    }
  else
    {
    /* useful for debugging */
    saved_tls_certificate = state->exp_tls_certificate;
    saved_tls_privatekey = state->exp_tls_privatekey;
    saved_tls_verify_certificates = state->exp_tls_verify_certificates;
    saved_tls_crl = state->exp_tls_crl;
    }
  }

rc = gnutls_certificate_allocate_credentials(&state->x509_cred);
exim_gnutls_err_check(US"gnutls_certificate_allocate_credentials");

/* remember: expand_check_tlsvar() is expand_check() but fiddling with
state members, assuming consistent naming; and expand_check() returns
false if expansion failed, unless expansion was forced to fail. */

/* check if we at least have a certificate, before doing expensive
D-H generation. */

if (!expand_check_tlsvar(tls_certificate))
  return DEFER;

/* certificate is mandatory in server, optional in client */

if ((state->exp_tls_certificate == NULL) ||
    (*state->exp_tls_certificate == '\0'))
  {
  if (state->host == NULL)
    return tls_error(US"no TLS server certificate is specified", NULL, NULL);
  else
    DEBUG(D_tls) debug_printf("TLS: no client certificate specified; okay\n");
  }

if (state->tls_privatekey && !expand_check_tlsvar(tls_privatekey))
  return DEFER;

/* tls_privatekey is optional, defaulting to same file as certificate */

if (state->tls_privatekey == NULL || *state->tls_privatekey == '\0')
  {
  state->tls_privatekey = state->tls_certificate;
  state->exp_tls_privatekey = state->exp_tls_certificate;
  }


if (state->exp_tls_certificate && *state->exp_tls_certificate)
  {
  DEBUG(D_tls) debug_printf("certificate file = %s\nkey file = %s\n",
      state->exp_tls_certificate, state->exp_tls_privatekey);

  if (state->received_sni)
    {
    if ((Ustrcmp(state->exp_tls_certificate, saved_tls_certificate) == 0) &&
        (Ustrcmp(state->exp_tls_privatekey, saved_tls_privatekey) == 0))
      {
      DEBUG(D_tls) debug_printf("TLS SNI: cert and key unchanged\n");
      }
    else
      {
      DEBUG(D_tls) debug_printf("TLS SNI: have a changed cert/key pair.\n");
      }
    }

  rc = gnutls_certificate_set_x509_key_file(state->x509_cred,
      CS state->exp_tls_certificate, CS state->exp_tls_privatekey,
      GNUTLS_X509_FMT_PEM);
  exim_gnutls_err_check(
      string_sprintf("cert/key setup: cert=%s key=%s",
        state->exp_tls_certificate, state->exp_tls_privatekey));
  DEBUG(D_tls) debug_printf("TLS: cert/key registered\n");
  } /* tls_certificate */

/* Set the trusted CAs file if one is provided, and then add the CRL if one is
provided. Experiment shows that, if the certificate file is empty, an unhelpful
error message is provided. However, if we just refrain from setting anything up
in that case, certificate verification fails, which seems to be the correct
behaviour. */

if (state->tls_verify_certificates && *state->tls_verify_certificates)
  {
  if (!expand_check_tlsvar(tls_verify_certificates))
    return DEFER;
  if (state->tls_crl && *state->tls_crl)
    if (!expand_check_tlsvar(tls_crl))
      return DEFER;

  if (!(state->exp_tls_verify_certificates &&
        *state->exp_tls_verify_certificates))
    {
    DEBUG(D_tls)
      debug_printf("TLS: tls_verify_certificates expanded empty, ignoring\n");
    /* With no tls_verify_certificates, we ignore tls_crl too */
    return OK;
    }
  }
else
  {
  DEBUG(D_tls)
    debug_printf("TLS: tls_verify_certificates not set or empty, ignoring\n");
  return OK;
  }

if (Ustat(state->exp_tls_verify_certificates, &statbuf) < 0)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "could not stat %s "
      "(tls_verify_certificates): %s", state->exp_tls_verify_certificates,
      strerror(errno));
  return DEFER;
  }

/* The test suite passes in /dev/null; we could check for that path explicitly,
but who knows if someone has some weird FIFO which always dumps some certs, or
other weirdness.  The thing we really want to check is that it's not a
directory, since while OpenSSL supports that, GnuTLS does not.
So s/!S_ISREG/S_ISDIR/ and change some messsaging ... */
if (S_ISDIR(statbuf.st_mode))
  {
  DEBUG(D_tls)
    debug_printf("verify certificates path is a dir: \"%s\"\n",
        state->exp_tls_verify_certificates);
  log_write(0, LOG_MAIN|LOG_PANIC,
      "tls_verify_certificates \"%s\" is a directory",
      state->exp_tls_verify_certificates);
  return DEFER;
  }

DEBUG(D_tls) debug_printf("verify certificates = %s size=" OFF_T_FMT "\n",
        state->exp_tls_verify_certificates, statbuf.st_size);

if (statbuf.st_size == 0)
  {
  DEBUG(D_tls)
    debug_printf("cert file empty, no certs, no verification, ignoring any CRL\n");
  return OK;
  }

cert_count = gnutls_certificate_set_x509_trust_file(state->x509_cred,
    CS state->exp_tls_verify_certificates, GNUTLS_X509_FMT_PEM);
if (cert_count < 0)
  {
  rc = cert_count;
  exim_gnutls_err_check(US"gnutls_certificate_set_x509_trust_file");
  }
DEBUG(D_tls) debug_printf("Added %d certificate authorities.\n", cert_count);

if (state->tls_crl && *state->tls_crl &&
    state->exp_tls_crl && *state->exp_tls_crl)
  {
  DEBUG(D_tls) debug_printf("loading CRL file = %s\n", state->exp_tls_crl);
  cert_count = gnutls_certificate_set_x509_crl_file(state->x509_cred,
      CS state->exp_tls_crl, GNUTLS_X509_FMT_PEM);
  if (cert_count < 0)
    {
    rc = cert_count;
    exim_gnutls_err_check(US"gnutls_certificate_set_x509_crl_file");
    }
  DEBUG(D_tls) debug_printf("Processed %d CRLs.\n", cert_count);
  }

return OK;
}




/*************************************************
*          Set X.509 state variables             *
*************************************************/

/* In GnuTLS, the registered cert/key are not replaced by a later
set of a cert/key, so for SNI support we need a whole new x509_cred
structure.  Which means various other non-re-expanded pieces of state
need to be re-set in the new struct, so the setting logic is pulled
out to this.

Arguments:
  state           exim_gnutls_state_st *

Returns:          OK/DEFER/FAIL
*/

static int
tls_set_remaining_x509(exim_gnutls_state_st *state)
{
int rc;
const host_item *host = state->host;  /* macro should be reconsidered? */

/* Create D-H parameters, or read them from the cache file. This function does
its own SMTP error messaging. This only happens for the server, TLS D-H ignores
client-side params. */

if (!state->host)
  {
  if (!dh_server_params)
    {
    rc = init_server_dh();
    if (rc != OK) return rc;
    }
  gnutls_certificate_set_dh_params(state->x509_cred, dh_server_params);
  }

/* Link the credentials to the session. */

rc = gnutls_credentials_set(state->session, GNUTLS_CRD_CERTIFICATE, state->x509_cred);
exim_gnutls_err_check(US"gnutls_credentials_set");

return OK;
}

/*************************************************
*            Initialize for GnuTLS               *
*************************************************/

/* Called from both server and client code. In the case of a server, errors
before actual TLS negotiation return DEFER.

Arguments:
  host            connected host, if client; NULL if server
  certificate     certificate file
  privatekey      private key file
  sni             TLS SNI to send, sometimes when client; else NULL
  cas             CA certs file
  crl             CRL file
  require_ciphers tls_require_ciphers setting

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(
    const host_item *host,
    const uschar *certificate,
    const uschar *privatekey,
    const uschar *sni,
    const uschar *cas,
    const uschar *crl,
    const uschar *require_ciphers,
    exim_gnutls_state_st **caller_state)
{
exim_gnutls_state_st *state;
int rc;
size_t sz;
const char *errpos;
uschar *p;
BOOL want_default_priorities;

if (!exim_gnutls_base_init_done)
  {
  DEBUG(D_tls) debug_printf("GnuTLS global init required.\n");

  rc = gnutls_global_init();
  exim_gnutls_err_check(US"gnutls_global_init");

#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
  DEBUG(D_tls)
    {
    gnutls_global_set_log_function(exim_gnutls_logger_cb);
    /* arbitrarily chosen level; bump upto 9 for more */
    gnutls_global_set_log_level(EXIM_GNUTLS_LIBRARY_LOG_LEVEL);
    }
#endif

  exim_gnutls_base_init_done = TRUE;
  }

if (host)
  {
  state = &state_client;
  memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));
  DEBUG(D_tls) debug_printf("initialising GnuTLS client session\n");
  rc = gnutls_init(&state->session, GNUTLS_CLIENT);
  }
else
  {
  state = &state_server;
  memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));
  DEBUG(D_tls) debug_printf("initialising GnuTLS server session\n");
  rc = gnutls_init(&state->session, GNUTLS_SERVER);
  }
exim_gnutls_err_check(US"gnutls_init");

state->host = host;

state->tls_certificate = certificate;
state->tls_privatekey = privatekey;
state->tls_require_ciphers = require_ciphers;
state->tls_sni = sni;
state->tls_verify_certificates = cas;
state->tls_crl = crl;

/* This handles the variables that might get re-expanded after TLS SNI;
that's tls_certificate, tls_privatekey, tls_verify_certificates, tls_crl */

DEBUG(D_tls)
  debug_printf("Expanding various TLS configuration options for session credentials.\n");
rc = tls_expand_session_files(state);
if (rc != OK) return rc;

/* These are all other parts of the x509_cred handling, since SNI in GnuTLS
requires a new structure afterwards. */

rc = tls_set_remaining_x509(state);
if (rc != OK) return rc;

/* set SNI in client, only */
if (host)
  {
  if (!expand_check_tlsvar(tls_sni))
    return DEFER;
  if (state->exp_tls_sni && *state->exp_tls_sni)
    {
    DEBUG(D_tls)
      debug_printf("Setting TLS client SNI to \"%s\"\n", state->exp_tls_sni);
    sz = Ustrlen(state->exp_tls_sni);
    rc = gnutls_server_name_set(state->session,
        GNUTLS_NAME_DNS, state->exp_tls_sni, sz);
    exim_gnutls_err_check(US"gnutls_server_name_set");
    }
  }
else if (state->tls_sni)
  DEBUG(D_tls) debug_printf("*** PROBABLY A BUG *** " \
      "have an SNI set for a client [%s]\n", state->tls_sni);

/* This is the priority string support,
http://www.gnu.org/software/gnutls/manual/html_node/Priority-Strings.html
and replaces gnutls_require_kx, gnutls_require_mac & gnutls_require_protocols.
This was backwards incompatible, but means Exim no longer needs to track
all algorithms and provide string forms for them. */

want_default_priorities = TRUE;

if (state->tls_require_ciphers && *state->tls_require_ciphers)
  {
  if (!expand_check_tlsvar(tls_require_ciphers))
    return DEFER;
  if (state->exp_tls_require_ciphers && *state->exp_tls_require_ciphers)
    {
    DEBUG(D_tls) debug_printf("GnuTLS session cipher/priority \"%s\"\n",
        state->exp_tls_require_ciphers);

    rc = gnutls_priority_init(&state->priority_cache,
        CS state->exp_tls_require_ciphers, &errpos);
    want_default_priorities = FALSE;
    p = state->exp_tls_require_ciphers;
    }
  }
if (want_default_priorities)
  {
  DEBUG(D_tls)
    debug_printf("GnuTLS using default session cipher/priority \"%s\"\n",
        exim_default_gnutls_priority);
  rc = gnutls_priority_init(&state->priority_cache,
      exim_default_gnutls_priority, &errpos);
  p = US exim_default_gnutls_priority;
  }

exim_gnutls_err_check(string_sprintf(
      "gnutls_priority_init(%s) failed at offset %ld, \"%.6s..\"",
      p, errpos - CS p, errpos));

rc = gnutls_priority_set(state->session, state->priority_cache);
exim_gnutls_err_check(US"gnutls_priority_set");

gnutls_db_set_cache_expiration(state->session, ssl_session_timeout);

/* Reduce security in favour of increased compatibility, if the admin
decides to make that trade-off. */
if (gnutls_compat_mode)
  {
#if LIBGNUTLS_VERSION_NUMBER >= 0x020104
  DEBUG(D_tls) debug_printf("lowering GnuTLS security, compatibility mode\n");
  gnutls_session_enable_compatibility_mode(state->session);
#else
  DEBUG(D_tls) debug_printf("Unable to set gnutls_compat_mode - GnuTLS version too old\n");
#endif
  }

*caller_state = state;
/* needs to happen before callbacks during handshake */
current_global_tls_state = state;
return OK;
}




/*************************************************
*            Extract peer information            *
*************************************************/

/* Called from both server and client code.
Only this is allowed to set state->peerdn and state->have_set_peerdn
and we use that to detect double-calls.

NOTE: the state blocks last while the TLS connection is up, which is fine
for logging in the server side, but for the client side, we log after teardown
in src/deliver.c.  While the session is up, we can twist about states and
repoint tls_* globals, but those variables used for logging or other variable
expansion that happens _after_ delivery need to have a longer life-time.

So for those, we get the data from POOL_PERM; the re-invoke guard keeps us from
doing this more than once per generation of a state context.  We set them in
the state context, and repoint tls_* to them.  After the state goes away, the
tls_* copies of the pointers remain valid and client delivery logging is happy.

tls_certificate_verified is a BOOL, so the tls_peerdn and tls_cipher issues
don't apply.

Arguments:
  state           exim_gnutls_state_st *

Returns:          OK/DEFER/FAIL
*/

static int
peer_status(exim_gnutls_state_st *state)
{
uschar cipherbuf[256];
const gnutls_datum *cert_list;
int old_pool, rc;
unsigned int cert_list_size = 0;
gnutls_protocol_t protocol;
gnutls_cipher_algorithm_t cipher;
gnutls_kx_algorithm_t kx;
gnutls_mac_algorithm_t mac;
gnutls_certificate_type_t ct;
gnutls_x509_crt_t crt;
uschar *p, *dn_buf;
size_t sz;

if (state->have_set_peerdn)
  return OK;
state->have_set_peerdn = TRUE;

state->peerdn = NULL;

/* tls_cipher */
cipher = gnutls_cipher_get(state->session);
protocol = gnutls_protocol_get_version(state->session);
mac = gnutls_mac_get(state->session);
kx = gnutls_kx_get(state->session);

string_format(cipherbuf, sizeof(cipherbuf),
    "%s:%s:%d",
    gnutls_protocol_get_name(protocol),
    gnutls_cipher_suite_get_name(kx, cipher, mac),
    (int) gnutls_cipher_get_key_size(cipher) * 8);

/* I don't see a way that spaces could occur, in the current GnuTLS
code base, but it was a concern in the old code and perhaps older GnuTLS
releases did return "TLS 1.0"; play it safe, just in case. */
for (p = cipherbuf; *p != '\0'; ++p)
  if (isspace(*p))
    *p = '-';
old_pool = store_pool;
store_pool = POOL_PERM;
state->ciphersuite = string_copy(cipherbuf);
store_pool = old_pool;
tls_cipher = state->ciphersuite;

/* tls_peerdn */
cert_list = gnutls_certificate_get_peers(state->session, &cert_list_size);

if (cert_list == NULL || cert_list_size == 0)
  {
  DEBUG(D_tls) debug_printf("TLS: no certificate from peer (%p & %d)\n",
      cert_list, cert_list_size);
  if (state->verify_requirement == VERIFY_REQUIRED)
    return tls_error(US"certificate verification failed",
        "no certificate received from peer", state->host);
  return OK;
  }

ct = gnutls_certificate_type_get(state->session);
if (ct != GNUTLS_CRT_X509)
  {
  const char *ctn = gnutls_certificate_type_get_name(ct);
  DEBUG(D_tls)
    debug_printf("TLS: peer cert not X.509 but instead \"%s\"\n", ctn);
  if (state->verify_requirement == VERIFY_REQUIRED)
    return tls_error(US"certificate verification not possible, unhandled type",
        ctn, state->host);
  return OK;
  }

#define exim_gnutls_peer_err(Label) do { \
  if (rc != GNUTLS_E_SUCCESS) { \
    DEBUG(D_tls) debug_printf("TLS: peer cert problem: %s: %s\n", (Label), gnutls_strerror(rc)); \
    if (state->verify_requirement == VERIFY_REQUIRED) { return tls_error((Label), gnutls_strerror(rc), state->host); } \
    return OK; } } while (0)

rc = gnutls_x509_crt_init(&crt);
exim_gnutls_peer_err(US"gnutls_x509_crt_init (crt)");

rc = gnutls_x509_crt_import(crt, &cert_list[0], GNUTLS_X509_FMT_DER);
exim_gnutls_peer_err(US"failed to import certificate [gnutls_x509_crt_import(cert 0)]");
sz = 0;
rc = gnutls_x509_crt_get_dn(crt, NULL, &sz);
if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
  {
  exim_gnutls_peer_err(US"getting size for cert DN failed");
  return FAIL; /* should not happen */
  }
dn_buf = store_get_perm(sz);
rc = gnutls_x509_crt_get_dn(crt, CS dn_buf, &sz);
exim_gnutls_peer_err(US"failed to extract certificate DN [gnutls_x509_crt_get_dn(cert 0)]");
state->peerdn = dn_buf;

return OK;
#undef exim_gnutls_peer_err
}




/*************************************************
*            Verify peer certificate             *
*************************************************/

/* Called from both server and client code.
*Should* be using a callback registered with
gnutls_certificate_set_verify_function() to fail the handshake if we dislike
the peer information, but that's too new for some OSes.

Arguments:
  state           exim_gnutls_state_st *
  error           where to put an error message

Returns:
  FALSE     if the session should be rejected
  TRUE      if the cert is okay or we just don't care
*/

static BOOL
verify_certificate(exim_gnutls_state_st *state, const char **error)
{
int rc;
unsigned int verify;

*error = NULL;

rc = peer_status(state);
if (rc != OK)
  {
  verify = GNUTLS_CERT_INVALID;
  *error = "not supplied";
  }
else
  {
  rc = gnutls_certificate_verify_peers2(state->session, &verify);
  }

/* Handle the result of verification. INVALID seems to be set as well
as REVOKED, but leave the test for both. */

if ((rc < 0) || (verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED)) != 0)
  {
  state->peer_cert_verified = FALSE;
  if (*error == NULL)
    *error = ((verify & GNUTLS_CERT_REVOKED) != 0) ? "revoked" : "invalid";

  DEBUG(D_tls)
    debug_printf("TLS certificate verification failed (%s): peerdn=%s\n",
        *error, state->peerdn ? state->peerdn : US"<unset>");

  if (state->verify_requirement == VERIFY_REQUIRED)
    {
    gnutls_alert_send(state->session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
    return FALSE;
    }
  DEBUG(D_tls)
    debug_printf("TLS verify failure overridden (host in tls_try_verify_hosts)\n");
  }
else
  {
  state->peer_cert_verified = TRUE;
  DEBUG(D_tls) debug_printf("TLS certificate verified: peerdn=%s\n",
      state->peerdn ? state->peerdn : US"<unset>");
  }

tls_peerdn = state->peerdn;

return TRUE;
}




/* ------------------------------------------------------------------------ */
/* Callbacks */

/* Logging function which can be registered with
 *   gnutls_global_set_log_function()
 *   gnutls_global_set_log_level() 0..9
 */
#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
static void
exim_gnutls_logger_cb(int level, const char *message)
{
  size_t len = strlen(message);
  if (len < 1)
    {
    DEBUG(D_tls) debug_printf("GnuTLS<%d> empty debug message\n", level);
    return;
    }
  DEBUG(D_tls) debug_printf("GnuTLS<%d>: %s%s", level, message,
      message[len-1] == '\n' ? "" : "\n");
}
#endif


/* Called after client hello, should handle SNI work.
This will always set tls_sni (state->received_sni) if available,
and may trigger presenting different certificates,
if state->trigger_sni_changes is TRUE.

Should be registered with
  gnutls_handshake_set_post_client_hello_function()

"This callback must return 0 on success or a gnutls error code to terminate the
handshake.".

For inability to get SNI information, we return 0.
We only return non-zero if re-setup failed.
*/

static int
exim_sni_handling_cb(gnutls_session_t session)
{
char sni_name[MAX_HOST_LEN];
size_t data_len = MAX_HOST_LEN;
exim_gnutls_state_st *state = current_global_tls_state;
unsigned int sni_type;
int rc, old_pool;

rc = gnutls_server_name_get(session, sni_name, &data_len, &sni_type, 0);
if (rc != GNUTLS_E_SUCCESS)
  {
  DEBUG(D_tls) {
    if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
      debug_printf("TLS: no SNI presented in handshake.\n");
    else
      debug_printf("TLS failure: gnutls_server_name_get(): %s [%d]\n",
        gnutls_strerror(rc), rc);
  };
  return 0;
  }

if (sni_type != GNUTLS_NAME_DNS)
  {
  DEBUG(D_tls) debug_printf("TLS: ignoring SNI of unhandled type %u\n", sni_type);
  return 0;
  }

/* We now have a UTF-8 string in sni_name */
old_pool = store_pool;
store_pool = POOL_PERM;
state->received_sni = string_copyn(US sni_name, data_len);
store_pool = old_pool;

/* We set this one now so that variable expansions below will work */
tls_sni = state->received_sni;

DEBUG(D_tls) debug_printf("Received TLS SNI \"%s\"%s\n", sni_name,
    state->trigger_sni_changes ? "" : " (unused for certificate selection)");

if (!state->trigger_sni_changes)
  return 0;

rc = tls_expand_session_files(state);
if (rc != OK)
  {
  /* If the setup of certs/etc failed before handshake, TLS would not have
  been offered.  The best we can do now is abort. */
  return GNUTLS_E_APPLICATION_ERROR_MIN;
  }

rc = tls_set_remaining_x509(state);
if (rc != OK) return GNUTLS_E_APPLICATION_ERROR_MIN;

return 0;
}




/* ------------------------------------------------------------------------ */
/* Exported functions */




/*************************************************
*       Start a TLS session in a server          *
*************************************************/

/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  require_ciphers  list of allowed ciphers or NULL

Returns:           OK on success
                   DEFER for errors before the start of the negotiation
                   FAIL for errors during the negotation; the server can't
                     continue running.
*/

int
tls_server_start(const uschar *require_ciphers)
{
int rc;
const char *error;
exim_gnutls_state_st *state = NULL;

/* Check for previous activation */
/* nb: this will not be TLS callout safe, needs reworking as part of that. */

if (tls_active >= 0)
  {
  tls_error(US"STARTTLS received after TLS started", "", NULL);
  smtp_printf("554 Already in TLS\r\n");
  return FAIL;
  }

/* Initialize the library. If it fails, it will already have logged the error
and sent an SMTP response. */

DEBUG(D_tls) debug_printf("initialising GnuTLS as a server\n");

rc = tls_init(NULL, tls_certificate, tls_privatekey,
    NULL, tls_verify_certificates, tls_crl,
    require_ciphers, &state);
if (rc != OK) return rc;

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

if (verify_check_host(&tls_verify_hosts) == OK)
  {
  DEBUG(D_tls) debug_printf("TLS: a client certificate will be required.\n");
  state->verify_requirement = VERIFY_REQUIRED;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUIRE);
  }
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  {
  DEBUG(D_tls) debug_printf("TLS: a client certificate will be requested but not required.\n");
  state->verify_requirement = VERIFY_OPTIONAL;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUEST);
  }
else
  {
  DEBUG(D_tls) debug_printf("TLS: a client certificate will not be requested.\n");
  state->verify_requirement = VERIFY_NONE;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_IGNORE);
  }

/* Register SNI handling; always, even if not in tls_certificate, so that the
expansion variable $tls_sni is always available. */

gnutls_handshake_set_post_client_hello_function(state->session,
    exim_sni_handling_cb);

/* Set context and tell client to go ahead, except in the case of TLS startup
on connection, where outputting anything now upsets the clients and tends to
make them disconnect. We need to have an explicit fflush() here, to force out
the response. Other smtp_printf() calls do not need it, because in non-TLS
mode, the fflush() happens when smtp_getc() is called. */

if (!tls_on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n");
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the GnuTLS library doesn't. */

gnutls_transport_set_ptr2(state->session,
    (gnutls_transport_ptr)fileno(smtp_in),
    (gnutls_transport_ptr)fileno(smtp_out));
state->fd_in = fileno(smtp_in);
state->fd_out = fileno(smtp_out);

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
do
  {
  rc = gnutls_handshake(state->session);
  } while ((rc == GNUTLS_E_AGAIN) ||
      (rc == GNUTLS_E_INTERRUPTED && !sigalrm_seen));
alarm(0);

if (rc != GNUTLS_E_SUCCESS)
  {
  tls_error(US"gnutls_handshake",
      sigalrm_seen ? "timed out" : gnutls_strerror(rc), NULL);
  /* It seems that, except in the case of a timeout, we have to close the
  connection right here; otherwise if the other end is running OpenSSL it hangs
  until the server times out. */

  if (!sigalrm_seen)
    {
    (void)fclose(smtp_out);
    (void)fclose(smtp_in);
    }

  return FAIL;
  }

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

/* Verify after the fact */

if (state->verify_requirement != VERIFY_NONE)
  {
  if (!verify_certificate(state, &error))
    {
    if (state->verify_requirement == VERIFY_OPTIONAL)
      {
      DEBUG(D_tls)
        debug_printf("TLS: continuing on only because verification was optional, after: %s\n",
            error);
      }
    else
      {
      tls_error(US"certificate verification failed", error, NULL);
      return FAIL;
      }
    }
  }

/* Figure out peer DN, and if authenticated, etc. */

rc = peer_status(state);
if (rc != OK) return rc;

/* Sets various Exim expansion variables; always safe within server */

extract_exim_vars_from_tls_state(state);

/* TLS has been set up. Adjust the input functions to read via TLS,
and initialize appropriately. */

state->xfer_buffer = store_malloc(ssl_xfer_buffer_size);

receive_getc = tls_getc;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;
receive_smtp_buffered = tls_smtp_buffered;

return OK;
}




/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Arguments:
  fd                the fd of the connection
  host              connected host (for messages)
  addr              the first address (not used)
  dhparam           DH parameter file (ignored, we're a client)
  certificate       certificate file
  privatekey        private key file
  sni               TLS SNI to send to remote host
  verify_certs      file for certificate verify
  verify_crl        CRL for verify
  require_ciphers   list of allowed ciphers or NULL
  timeout           startup timeout

Returns:            OK/DEFER/FAIL (because using common functions),
                    but for a client, DEFER and FAIL have the same meaning
*/

int
tls_client_start(int fd, host_item *host,
    address_item *addr ARG_UNUSED, uschar *dhparam ARG_UNUSED,
    uschar *certificate, uschar *privatekey, uschar *sni,
    uschar *verify_certs, uschar *verify_crl,
    uschar *require_ciphers, int timeout)
{
int rc;
const char *error;
exim_gnutls_state_st *state = NULL;

DEBUG(D_tls) debug_printf("initialising GnuTLS as a client on fd %d\n", fd);

rc = tls_init(host, certificate, privatekey,
    sni, verify_certs, verify_crl, require_ciphers, &state);
if (rc != OK) return rc;

gnutls_dh_set_prime_bits(state->session, EXIM_CLIENT_DH_MIN_BITS);

if (verify_certs == NULL)
  {
  DEBUG(D_tls) debug_printf("TLS: server certificate verification not required\n");
  state->verify_requirement = VERIFY_NONE;
  /* we still ask for it, to log it, etc */
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUEST);
  }
else
  {
  DEBUG(D_tls) debug_printf("TLS: server certificate verification required\n");
  state->verify_requirement = VERIFY_REQUIRED;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUIRE);
  }

gnutls_transport_set_ptr(state->session, (gnutls_transport_ptr)fd);
state->fd_in = fd;
state->fd_out = fd;

/* There doesn't seem to be a built-in timeout on connection. */

sigalrm_seen = FALSE;
alarm(timeout);
do
  {
  rc = gnutls_handshake(state->session);
  } while ((rc == GNUTLS_E_AGAIN) ||
      (rc == GNUTLS_E_INTERRUPTED && !sigalrm_seen));
alarm(0);

if (rc != GNUTLS_E_SUCCESS)
  return tls_error(US"gnutls_handshake",
      sigalrm_seen ? "timed out" : gnutls_strerror(rc), state->host);

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

/* Verify late */

if (state->verify_requirement != VERIFY_NONE &&
    !verify_certificate(state, &error))
  return tls_error(US"certificate verification failed", error, state->host);

/* Figure out peer DN, and if authenticated, etc. */

rc = peer_status(state);
if (rc != OK) return rc;

/* Sets various Exim expansion variables; may need to adjust for ACL callouts */

extract_exim_vars_from_tls_state(state);

return OK;
}




/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the TLS session in the parent process).

Arguments:   TRUE if gnutls_bye is to be called
Returns:     nothing
*/

void
tls_close(BOOL shutdown)
{
exim_gnutls_state_st *state = current_global_tls_state;

if (tls_active < 0) return;  /* TLS was not active */

if (shutdown)
  {
  DEBUG(D_tls) debug_printf("tls_close(): shutting down TLS\n");
  gnutls_bye(state->session, GNUTLS_SHUT_WR);
  }

gnutls_deinit(state->session);

memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));

if ((state_server.session == NULL) && (state_client.session == NULL))
  {
  gnutls_global_deinit();
  exim_gnutls_base_init_done = FALSE;
  }

tls_active = -1;
}




/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the GnuTLS reading function.

This feeds DKIM and should be used for all message-body reads.

Arguments:  none
Returns:    the next character or EOF
*/

int
tls_getc(void)
{
exim_gnutls_state_st *state = current_global_tls_state;
if (state->xfer_buffer_lwm >= state->xfer_buffer_hwm)
  {
  ssize_t inbytes;

  DEBUG(D_tls) debug_printf("Calling gnutls_record_recv(%p, %p, %u)\n",
    state->session, state->xfer_buffer, ssl_xfer_buffer_size);

  if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
  inbytes = gnutls_record_recv(state->session, state->xfer_buffer,
    ssl_xfer_buffer_size);
  alarm(0);

  /* A zero-byte return appears to mean that the TLS session has been
     closed down, not that the socket itself has been closed down. Revert to
     non-TLS handling. */

  if (inbytes == 0)
    {
    DEBUG(D_tls) debug_printf("Got TLS_EOF\n");

    receive_getc = smtp_getc;
    receive_ungetc = smtp_ungetc;
    receive_feof = smtp_feof;
    receive_ferror = smtp_ferror;
    receive_smtp_buffered = smtp_buffered;

    gnutls_deinit(state->session);
    state->session = NULL;
    tls_active = -1;
    tls_bits = 0;
    tls_certificate_verified = FALSE;
    tls_channelbinding_b64 = NULL;
    tls_cipher = NULL;
    tls_peerdn = NULL;

    return smtp_getc();
    }

  /* Handle genuine errors */

  else if (inbytes < 0)
    {
    record_io_error(state, (int) inbytes, US"recv", NULL);
    state->xfer_error = 1;
    return EOF;
    }
#ifndef DISABLE_DKIM
  dkim_exim_verify_feed(state->xfer_buffer, inbytes);
#endif
  state->xfer_buffer_hwm = (int) inbytes;
  state->xfer_buffer_lwm = 0;
  }

/* Something in the buffer; return next uschar */

return state->xfer_buffer[state->xfer_buffer_lwm++];
}




/*************************************************
*          Read bytes from TLS channel           *
*************************************************/

/* This does not feed DKIM, so if the caller uses this for reading message body,
then the caller must feed DKIM.
Arguments:
  buff      buffer of data
  len       size of buffer

Returns:    the number of bytes read
            -1 after a failed read
*/

int
tls_read(uschar *buff, size_t len)
{
exim_gnutls_state_st *state = current_global_tls_state;
ssize_t inbytes;

if (len > INT_MAX)
  len = INT_MAX;

if (state->xfer_buffer_lwm < state->xfer_buffer_hwm)
  DEBUG(D_tls)
    debug_printf("*** PROBABLY A BUG *** " \
        "tls_read() called with data in the tls_getc() buffer, %d ignored\n",
        state->xfer_buffer_hwm - state->xfer_buffer_lwm);

DEBUG(D_tls)
  debug_printf("Calling gnutls_record_recv(%p, %p, " SIZE_T_FMT ")\n",
      state->session, buff, len);

inbytes = gnutls_record_recv(state->session, buff, len);
if (inbytes > 0) return inbytes;
if (inbytes == 0)
  {
  DEBUG(D_tls) debug_printf("Got TLS_EOF\n");
  }
else record_io_error(state, (int)inbytes, US"recv", NULL);

return -1;
}




/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  buff      buffer of data
  len       number of bytes

Returns:    the number of bytes after a successful write,
            -1 after a failed write
*/

int
tls_write(const uschar *buff, size_t len)
{
ssize_t outbytes;
size_t left = len;
exim_gnutls_state_st *state = current_global_tls_state;

DEBUG(D_tls) debug_printf("tls_do_write(%p, " SIZE_T_FMT ")\n", buff, left);
while (left > 0)
  {
  DEBUG(D_tls) debug_printf("gnutls_record_send(SSL, %p, " SIZE_T_FMT ")\n",
      buff, left);
  outbytes = gnutls_record_send(state->session, buff, left);

  DEBUG(D_tls) debug_printf("outbytes=" SSIZE_T_FMT "\n", outbytes);
  if (outbytes < 0)
    {
    record_io_error(state, outbytes, US"send", NULL);
    return -1;
    }
  if (outbytes == 0)
    {
    record_io_error(state, 0, US"send", US"TLS channel closed on write");
    return -1;
    }

  left -= outbytes;
  buff += outbytes;
  }

if (len > INT_MAX)
  {
  DEBUG(D_tls)
    debug_printf("Whoops!  Wrote more bytes (" SIZE_T_FMT ") than INT_MAX\n",
        len);
  len = INT_MAX;
  }

return (int) len;
}




/*************************************************
*            Random number generation            *
*************************************************/

/* Pseudo-random number generation.  The result is not expected to be
cryptographically strong but not so weak that someone will shoot themselves
in the foot using it as a nonce in input in some email header scheme or
whatever weirdness they'll twist this into.  The result should handle fork()
and avoid repeating sequences.  OpenSSL handles that for us.

Arguments:
  max       range maximum
Returns     a random number in range [0, max-1]
*/

#ifdef HAVE_GNUTLS_RND
int
vaguely_random_number(int max)
{
unsigned int r;
int i, needed_len;
uschar *p;
uschar smallbuf[sizeof(r)];

if (max <= 1)
  return 0;

needed_len = sizeof(r);
/* Don't take 8 times more entropy than needed if int is 8 octets and we were
 * asked for a number less than 10. */
for (r = max, i = 0; r; ++i)
  r >>= 1;
i = (i + 7) / 8;
if (i < needed_len)
  needed_len = i;

i = gnutls_rnd(GNUTLS_RND_NONCE, smallbuf, needed_len);
if (i < 0)
  {
  DEBUG(D_all) debug_printf("gnutls_rnd() failed, using fallback.\n");
  return vaguely_random_number_fallback(max);
  }
r = 0;
for (p = smallbuf; needed_len; --needed_len, ++p)
  {
  r *= 256;
  r += *p;
  }

/* We don't particularly care about weighted results; if someone wants
 * smooth distribution and cares enough then they should submit a patch then. */
return r % max;
}
#else /* HAVE_GNUTLS_RND */
int
vaguely_random_number(int max)
{
  return vaguely_random_number_fallback(max);
}
#endif /* HAVE_GNUTLS_RND */




/*************************************************
*  Let tls_require_ciphers be checked at startup *
*************************************************/

/* The tls_require_ciphers option, if set, must be something which the
library can parse.

Returns:     NULL on success, or error message
*/

uschar *
tls_validate_require_cipher(void)
{
int rc;
uschar *expciphers = NULL;
gnutls_priority_t priority_cache;
const char *errpos;

#define validate_check_rc(Label) do { \
  if (rc != GNUTLS_E_SUCCESS) { if (exim_gnutls_base_init_done) gnutls_global_deinit(); \
  return string_sprintf("%s failed: %s", (Label), gnutls_strerror(rc)); } } while (0)
#define return_deinit(Label) do { gnutls_global_deinit(); return (Label); } while (0)

if (exim_gnutls_base_init_done)
  log_write(0, LOG_MAIN|LOG_PANIC,
      "already initialised GnuTLS, Exim developer bug");

rc = gnutls_global_init();
validate_check_rc(US"gnutls_global_init()");
exim_gnutls_base_init_done = TRUE;

if (!(tls_require_ciphers && *tls_require_ciphers))
  return_deinit(NULL);

if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers))
  return_deinit(US"failed to expand tls_require_ciphers");

if (!(expciphers && *expciphers))
  return_deinit(NULL);

DEBUG(D_tls)
  debug_printf("tls_require_ciphers expands to \"%s\"\n", expciphers);

rc = gnutls_priority_init(&priority_cache, CS expciphers, &errpos);
validate_check_rc(string_sprintf(
      "gnutls_priority_init(%s) failed at offset %ld, \"%.8s..\"",
      expciphers, errpos - CS expciphers, errpos));

#undef return_deinit
#undef validate_check_rc
gnutls_global_deinit();

return NULL;
}




/*************************************************
*         Report the library versions.           *
*************************************************/

/* See a description in tls-openssl.c for an explanation of why this exists.

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
tls_version_report(FILE *f)
{
fprintf(f, "Library version: GnuTLS: Compile: %s\n"
           "                         Runtime: %s\n",
           LIBGNUTLS_VERSION,
           gnutls_check_version(NULL));
}

/* End of tls-gnu.c */
