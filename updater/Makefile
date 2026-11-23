TITLE_ID = INAP00019
TARGET   = updater
OBJS     = main.o wb_sha256.o wb_sfo.o

LIBS   = -lSceAppMgr_stub -lScePromoterUtil_stub -lSceSysmodule_stub \
         -lSceLibKernel_stub -lSceIofilemgr_stub -lSceRtc_stub
PREFIX = arm-vita-eabi
CC     = $(PREFIX)-gcc
CFLAGS = -Wl,-q -Wall -Wextra -Werror -O3 -marm

all: $(TARGET).vpk

main.o: ../source/wb_paf_release.h

wb_sha256.o: ../source/wb_sha256.c
	$(CC) $(CFLAGS) -c $< -o $@
wb_sfo.o: ../source/wb_sfo.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).vpk: eboot.bin param.sfo
	vita-pack-vpk -s param.sfo -b eboot.bin $@

eboot.bin: $(TARGET).velf
	vita-make-fself $< $@

param.sfo:
	vita-mksfoex -s TITLE_ID=$(TITLE_ID) -s APP_VER=01.00 'Workbench Updater' $@

%.velf: %.elf
	python3 ../source/check_core_layout.py $<
	vita-elf-create $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) -Wl,--defsym=__sce_headroom=0x1000 $^ $(LIBS) -o $@

clean:
	@rm -f $(TARGET).vpk $(TARGET).velf $(TARGET).elf $(OBJS) eboot.bin param.sfo

send:
	curl -T $(TARGET).vpk ftp://$(PSVITAIP):1337/ux0:/VITA-POC/
