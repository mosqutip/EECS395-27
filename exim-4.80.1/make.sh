#!/usr/bin/bash

OBJ_LOOKUPS="buildlookups"

EXIM_PERL=""

OBJ_WITH_CONTENT_SCAN="malware.o mime.o regex.o spam.o spool_mbox.o"

OBJ_WITH_OLD_DEMIME="demime.o"

OBJ_EXPERIMENTAL="bmi_spam.o spf.o srs.o dcc.o"

OBJ_EXIM="acl.o child.o crypt16.o daemon.o dbfn.o debug.o deliver.o directory.o dns.o drtables.o enq.o exim.o expand.o filter.o filtertest.o globals.o dkim.o header.o host.o ip.o log.o lss.o match.o moan.o os.o parse.o queue.o rda.o readconf.o receive.o retry.o rewrite.o rfc2047.o route.o search.o sieve.o smtp_in.o smtp_out.o spool_in.o spool_out.o std-crypto.o store.o string.o tls.o tod.o transport.o tree.o verify.o $OBJ_LOOKUPS local_scan.o $EXIM_PERL $OBJ_WITH_CONTENT_SCAN $OBJ_WITH_OLD_DEMIME $OBJ_EXPERIMENTAL"

FE=""

PURIFY=""

LNCC="gcc"

frama-c -print -cpp-command "gcc -C -E $FE$PURIFY $LNCC -I. -I../build-Linux-x86_64 $OBJ_EXIM tls-gnu.c" tls-gnu.c
