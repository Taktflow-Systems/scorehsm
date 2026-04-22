# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Taktflow Systems

CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Werror -I../../../include
TARGET ?=
EXEEXT =

ifeq ($(OS),Windows_NT)
ifeq ($(strip $(TARGET)),)
TARGET := x86_64-pc-windows-gnu
endif
RM := cmd /C if exist ffi_link_test del /Q ffi_link_test & if exist ffi_link_test.exe del /Q ffi_link_test.exe
endif

ifneq ($(strip $(TARGET)),)
STATICLIB := ../../../target/$(TARGET)/debug/libscorehsm_host.a
BUILD_CMD := cargo build -p scorehsm-host --features ffi --target $(TARGET)
else
STATICLIB := ../../../target/debug/libscorehsm_host.a
BUILD_CMD := cargo build -p scorehsm-host --features ffi
endif

ifneq ($(findstring windows-gnu,$(TARGET)),)
EXEEXT = .exe
NATIVE_LIBS ?= -lws2_32 -lbcrypt -ladvapi32 -luserenv -lkernel32 -lntdll
endif

.PHONY: all clean

all: ffi_link_test$(EXEEXT)

$(STATICLIB):
	$(BUILD_CMD)

ffi_link_test$(EXEEXT): ffi_link_test.c $(STATICLIB)
	$(CC) $(CFLAGS) ffi_link_test.c $(STATICLIB) $(NATIVE_LIBS) -o $@

clean:
	$(RM) ffi_link_test ffi_link_test.exe
