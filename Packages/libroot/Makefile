ARCH = arm64 arm64e
TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME=roothide

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libroot

libroot_FILES = libroot.c
libroot_CFLAGS = 
libroot_INSTALL_PATH = /usr/lib

include $(THEOS_MAKE_PATH)/library.mk

after-package::
	cp ./packages/*.deb ./libroot.deb

before-package::
	rm -rf ./packages/*

clean::
	rm -rf ./packages/*
