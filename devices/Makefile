PATH := $(abspath ../sdk/esp-open-sdk/xtensa-lx106-elf/bin):$(PATH)
SIGN_BIN = $(abspath tools/sign_bin.py)

%:
	@:

rebuild:
	$(MAKE) clean
	$(MAKE) all

all:
	$(MAKE) main
	$(MAKE) ota

clean:
	$(MAKE) clean_main
	$(MAKE) clean_ota

main:
	cd ESPY_HOUSE && $(MAKE) all && $(SIGN_BIN) firmware/espy_house.bin

clean_main:
	cd ESPY_HOUSE && $(MAKE) clean

rebuild_main:
	$(MAKE) clean_main && $(MAKE) main

ota:
	cd ESPY_OTA && $(MAKE) all && $(SIGN_BIN) firmware/espy_ota.bin && rm -rf build && ESPY_INSTALLER=1 $(MAKE) all && $(SIGN_BIN) firmware/espy_installer.bin && \
	cat fullhaaboot/fullrboot.bin firmware/espy_installer.bin fullhaaboot/tasmota_append.bin >firmware/full_espy_boot.bin && $(SIGN_BIN) firmware/full_espy_boot.bin

clean_ota:
	cd ESPY_OTA && $(MAKE) clean

rebuild_ota:
	$(MAKE) clean_ota && $(MAKE) ota
