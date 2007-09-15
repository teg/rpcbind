INCLUDES = -I$(srcdir)/tirpc -DPORTMAP -DINET6 -DVERSION="\"$(VERSION)\"" \
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
rpcinfo_LDFLAGS =       -lpthread -ltirpc
rpcinfo_LDADD   =       $(LIB_TIRPC)


rpcbind_LDFLAGS = -lpthread -ltirpc
rpcbind_LDADD = $(LIB_TIRPC)
AM_CPPFLAGS = -I/usr/include/tirpc -DCHECK_LOCAL -DPORTMAP \
                       -DFACILITY=LOG_MAIL -DSEVERITY=LOG_INFO

$(rpcbind_OBJECTS) :    security.o util.o check_bound.o pmap_svc.o \
                        rpcb_svc.o rpcb_svc_com.o rpcb_svc_4.o \
                        rpcb_stat.o rpcbind.o warmstart.o 
$(rpcinfo_OBJECTS) :    rpcinfo.o                       
     
