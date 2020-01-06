## Makefile.am

AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include  
AM_CFLAGS = -Wall -g 
sbin_PROGRAMS = dumpinodes.f2fs
noinst_HEADERS = $(top_srcdir)/fsck/common.h $(top_srcdir)/fsck/dict.h $(top_srcdir)/fsck/dqblk_v2.h $(top_srcdir)/fsck/f2fs.h $(top_srcdir)/fsck/fsck.h $(top_srcdir)/fsck/node.h $(top_srcdir)/fsck/quotaio.h $(top_srcdir)/fsck/quotaio_tree.h $(top_srcdir)/fsck/quotaio_v2.h $(top_srcdir)/fsck/xattr.h
include_HEADERS = $(top_srcdir)/include/quota.h
dumpinodes_f2fs_SOURCES = main.c | $(top_srcdir)/fsck/fsck.c $(top_srcdir)/fsck/dump.c $(top_srcdir)/fsck/mount.c \
		$(top_srcdir)/fsck/node.c $(top_srcdir)/fsck/segment.c $(top_srcdir)/fsck/dir.c $(top_srcdir)/fsck/sload.c $(top_srcdir)/fsck/xattr.c \
		$(top_srcdir)/fsck/dict.c $(top_srcdir)/fsck/mkquota.c $(top_srcdir)/fsck/quotaio.c $(top_srcdir)/fsck/quotaio_tree.c $(top_srcdir)/fsck/quotaio_v2.c
dumpinodes_f2fs_LDADD = ${libselinux_LIBS} ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la

