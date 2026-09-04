#
#    Xenon - a lightweight cryptographical tool with PQC by default
#    Copyright (C) 2026 prexno
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

CC := gcc

TARGET := bip39

SRC_DIR := src
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
TARGET_DIR := $(BUILD_DIR)/target

CFLAGS := -Wall -Wextra -O2 \
          -I/usr/local/include \
          -I$(SRC_DIR)

LDFLAGS := -L/usr/local/lib \
           -Wl,-rpath,/usr/local/lib

LDLIBS := -lwolfssl

SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

EXEC := $(TARGET_DIR)/$(TARGET)

.PHONY: all clean rebuild

all: $(EXEC)

$(EXEC): $(OBJS)
	@mkdir -p $(TARGET_DIR)
	@echo "  LD    $@"
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC    $<"
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJS:.o=.d)

rebuild: clean
	$(MAKE) all

clean:
	rm -rf $(BUILD_DIR)

