/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*
 * warmstart.c
 * Allows for gathering of registrations from an earlier dumped file.
 *
 * Copyright (c) 1990 by Sun Microsystems, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_prot.h>
#include <rpc/xdr.h>
#ifdef PORTMAP
#include <netinet/in.h>
#include <rpc/pmap_prot.h>
#endif
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "rpcbind.h"

#ifndef RPCBIND_STATEDIR
#define RPCBIND_STATEDIR "/tmp"
#endif

/* These files keep the pmap_list and rpcb_list in XDR format */
#define	RPCBFILE	RPCBIND_STATEDIR "/rpcbind.xdr"
#ifdef PORTMAP
#define	PMAPFILE	RPCBIND_STATEDIR "/portmap.xdr"
#endif

static bool_t write_struct __P((char *, xdrproc_t, void *));
static bool_t read_struct __P((char *, xdrproc_t, void *));

static bool_t
write_struct(char *filename, xdrproc_t structproc, void *list)
{
	FILE *fp;
	XDR xdrs;
	mode_t omask;

	omask = umask(077);
	fp = fopen(filename, "w");
	if (fp == NULL) {
		int i;

		for (i = 0; i < 10; i++)
			close(i);
		fp = fopen(filename, "w");
		if (fp == NULL) {
			syslog(LOG_ERR,
				"cannot open file = %s for writing", filename);
			syslog(LOG_ERR, "cannot save any registration");
			return (FALSE);
		}
	}
	(void) umask(omask);
	xdrstdio_create(&xdrs, fp, XDR_ENCODE);

	if (structproc(&xdrs, list) == FALSE) {
		syslog(LOG_ERR, "xdr_%s: failed", filename);
		fclose(fp);
		return (FALSE);
	}
	XDR_DESTROY(&xdrs);
	fclose(fp);
	return (TRUE);
}

static bool_t
read_struct(char *filename, xdrproc_t structproc, void *list)
{
	FILE *fp;
	XDR xdrs;
	struct stat sbuf;
	 
	if (debugging)
		fprintf(stderr, "rpcbind: using '%s' startup file\n", filename);

	if ((fp = fopen(filename, "r")) == NULL) {
		syslog(LOG_ERR,
			"Cannot open '%s' file for reading, errno %d (%s)", 
			filename, errno, strerror(errno));
		goto error;
	}

	xdrstdio_create(&xdrs, fp, XDR_DECODE);
	if (structproc(&xdrs, list) == FALSE) {
		fprintf(stderr, "rpcbind: xdr_%s: failed\n", filename);
		fclose(fp);
		goto error;
	}
	XDR_DESTROY(&xdrs);

	fclose(fp);
	if (unlink(filename) < 0) {
		syslog(LOG_ERR, "Cannot unlink '%s', errno %d (%s)", 
			filename, errno, strerror(errno));
	}
	return (TRUE);

error:	
	if (errno != ENOENT && unlink(filename) < 0) {
		syslog(LOG_ERR, "Cannot unlink '%s', errno %d (%s)", 
			filename, errno, strerror(errno));
	}
	if (debugging)
		fprintf(stderr, "rpcbind: will start from scratch\n");
	return (FALSE);
}

void
write_warmstart()
{
	(void) write_struct(RPCBFILE, (xdrproc_t)xdr_rpcblist_ptr, &list_rbl);
#ifdef PORTMAP
	(void) write_struct(PMAPFILE, (xdrproc_t)xdr_pmaplist_ptr, &list_pml);
#endif

}

void
read_warmstart()
{
	rpcblist_ptr tmp_rpcbl = NULL;
#ifdef PORTMAP
	struct pmaplist *tmp_pmapl = NULL;
#endif
	int rc;

	rc = read_struct(RPCBFILE, (xdrproc_t)xdr_rpcblist_ptr, &tmp_rpcbl);
	if (rc == TRUE) {
		rpcblist *pos, **tail;

		/* The current rpcblist contains only the registrations
		 * for rpcbind and portmap. We keep those, since the
		 * info from the warm start file may be stale if the
		 * netconfig file was changed in the meantime.
		 * From the warm start file, we weed out any rpcbind info.
		 */
		for (tail = &list_rbl; *tail; tail = &(*tail)->rpcb_next)
			;
		while ((pos = tmp_rpcbl) != NULL) {
			tmp_rpcbl = pos->rpcb_next;
			if (pos->rpcb_map.r_prog != RPCBPROG) {
				*tail = pos;
				tail = &pos->rpcb_next;
			} else {
				free(pos);
			}
		}
		*tail = NULL;
	}
#ifdef PORTMAP
	rc = read_struct(PMAPFILE, (xdrproc_t)xdr_pmaplist_ptr, &tmp_pmapl);
	if (rc == TRUE) {
		struct pmaplist *pos, **tail;

		/* The current pmaplist contains only the registrations
		 * for rpcbind and portmap. We keep those, since the
		 * info from the warm start file may be stale if the
		 * netconfig file was changed in the meantime.
		 * From the warm start file, we weed out any rpcbind info.
		 */
		for (tail = &list_pml; *tail; tail = &(*tail)->pml_next)
			;
		while ((pos = tmp_pmapl) != NULL) {
			tmp_pmapl = pos->pml_next;
			if (pos->pml_map.pm_prog != PMAPPROG) {
				*tail = pos;
				tail = &pos->pml_next;
			} else {
				free(pos);
			}
		}
		*tail = NULL;
	}
#endif

	return;
}
