TITLE_ID = INAP00020
TARGET   = testapp

LIBS   = -lSceAppMgr_stub -lSceLibKernel_stub -lSceIofilemgr_stub -lScePower_stub
PREFIX = arm-vita-eabi
CC     = $(PREFIX)-gcc
CFLAGS = -Wall -Wextra -Werror -O2 -marm

all: $(TARGET).vpk

$(TARGET).vpk: eboot.bin param.sfo
	vita-pack-vpk -s param.sfo -b eboot.bin $@

eboot.bin: $(TARGET).velf
	vita-make-fself $< $@

param.sfo:
	vita-mksfoex -s TITLE_ID=$(TITLE_ID) -s APP_VER=01.01 'Workbench TestApp' $@

%.velf: %.elf
	vita-elf-create $< $@

$(TARGET).elf: main.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

clean:
	@rm -f $(TARGET).vpk $(TARGET).velf $(TARGET).elf main.o eboot.bin param.sfo
