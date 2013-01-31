AUTOMAKE_OPTIONS= foreign
INCLUDES=-I../common -I$(top_srcdir)/include
bin_PROGRAMS=upolicy
upolicy_SOURCES=main.c policy.c mul_timer.c
upolicy_LDADD=../common/libutil.a -lpthread
