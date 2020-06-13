PROGRAM = haa_ir_capture

PATH := $(shell pwd)/../../sdk/esp-open-sdk/xtensa-lx106-elf/bin:$(PATH)

include $(abspath ../../sdk/esp-open-rtos/common.mk)

monitor:
	$(FILTEROUTPUT) --port $(ESPPORT) --baud 115200 --elf $(PROGRAM_OUT)
