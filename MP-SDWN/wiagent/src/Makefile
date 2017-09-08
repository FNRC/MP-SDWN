AKEFLAGS += --no-print-directory

PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
PKG_CONFIG ?= pkg-config

MKDIR ?= mkdir -p
INSTALL ?= install
CC ?= "gcc"

CFLAGS ?= -MMD -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common \
		  -DCONFIG_DRIVER_NL80211 -DLIBEVENT2_MGMT_FRAME 

LIBS += -levent -lnl-tiny -ljson-c

OBJS += ./main.o
OBJS += ./utils/common.o
OBJS += ./utils/wiagent_event.o
OBJS += ./utils/wpa_debug.o
OBJS += ./drivers/driver_nl80211.o
OBJS += ./drivers/drivers.o
OBJS += ./agent/controller_event.o
OBJS += ./agent/push.o
OBJS += ./agent/subscription.o
OBJS += ./agent/vap.o
OBJS += ./agent/stainfo_handler.o
OBJS += ./ap/config_file.o
OBJS += ./ap/hostapd.o
OBJS += ./ap/beacon.o
OBJS += ./ap/hw_features.o
OBJS += ./ap/wiagent_80211.o
OBJS += ./ap/sta_info.o

-include $(OBJS:%.o=%.d)

all: wiagent

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

wiagent: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o wiagent

.PHONY : clean
