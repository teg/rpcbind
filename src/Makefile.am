INCLUDES = $(TIRPC_CFLAGS) -DPORTMAP -DINET6 -DVERSION="\"$(VERSION)\"" \
                                                -D_GNU_SOURCE -Wall -pipe
if DEBUG
INCLUDES +=	-DRPCBIND_DEBUG -DSVC_RUN_DEBUG -DDEBUG_RMTCALL
INCLUDES +=	-DND_DEBUG -DBIND_DEBUG
endif

if WARMSTART
INCLUDES +=	-DWARMSTART
endif

if LIBWRAP
INCLUDES +=	-DLIBWRAP
endif


bin_PROGRAMS = rpcbind rpcinfo

rpcbind_SOURCES =       check_bound.c rpcbind.c \
                        rpcb_svc_4.c rpcb_svc_com.c \
                        util.c pmap_svc.c rpcb_stat.c \
                        rpcb_svc.c security.c warmstart.c \
                        rpcbind.h

rpcinfo_SOURCES =       rpcinfo.c
rpcinfo_LDFLAGS =       -lpthread
rpcinfo_LDADD   =       $(TIRPC_LIBS)


rpcbind_LDFLAGS = -lpthread
rpcbind_CFLAGS = $(TIRPC_CFLAGS)
rpcbind_LDADD = $(TIRPC_LIBS)
AM_CPPFLAGS = -DCHECK_LOCAL -DPORTMAP \
                       -DFACILITY=LOG_MAIL -DSEVERITY=LOG_INFO
     
