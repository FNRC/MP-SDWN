#
# OpenWrt Makefile for wmaster program
#
# A wireless network program processing the the connection process of the STA.

include $(TOPDIR)/rules.mk

PKG_NAME:=wiagent
PKG_RELEASE:=1.0.0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/wiagent
	SECTION:=net
	CATEGORY:=Network
	TITLE:=wiagent
	DEPENDS:= +libevent2 +libnl-tiny +libjson-c
endef

TARGET_CPPFLAGS:= \
	-I$(STAGING_DIR)/usr/include/json-c \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE

# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/wiagent/description
	802.11 wireless access controller
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/wiagent/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wiagent $(1)/bin/
endef

$(eval $(call BuildPackage,wiagent))

