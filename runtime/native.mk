CC ?= gcc
AR ?= ar
MP=micropython_embed
SRCS := game.c $(wildcard $(MP)/py/*.c) $(MP)/shared/runtime/gchelper_generic.c
CFLAGS += -std=gnu99 -I. -I$(MP) -I$(MP)/port -DNDEBUG -Os -fno-strict-aliasing -ffunction-sections -fdata-sections
OBJDIR ?= obj-host
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
.PHONY: all
all: $(OBJDIR)/libwbgame.a
$(OBJDIR)/libwbgame.a: $(OBJS)
	$(AR) rcs $@ $^
$(OBJDIR)/%.o: %.c game_blob.inc mpconfigport.h wb_game.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
