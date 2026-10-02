PYTHON ?= python3
TARGET := targets/msm8930-r1.2
OUT := out/msm8930-r1.2

.PHONY: check verify test listings

check: verify test

verify:
	$(PYTHON) tools/rom.py verify $(TARGET)

test:
	$(PYTHON) -m unittest discover -s tests -v

listings: verify
	mkdir -p $(OUT)
	$(PYTHON) tools/rom.py disasm $(TARGET) 0x0 0x18c > $(OUT)/reset.asm
	$(PYTHON) tools/rom.py disasm $(TARGET) 0x8ed0 0x30 > $(OUT)/rom-dispatch.asm
	$(PYTHON) tools/rom.py disasm $(TARGET) 0x6720 0xa0 > $(OUT)/boot-main.asm
	$(PYTHON) tools/rom.py disasm $(TARGET) 0x8b24 0x1a8 > $(OUT)/image-loader.asm
	$(PYTHON) tools/rom.py disasm $(TARGET) 0x63b8 0xe4 > $(OUT)/recovery.asm
	$(PYTHON) tools/rom.py words $(TARGET) 0x10ce0 24 > $(OUT)/boot-stages.txt
	$(PYTHON) tools/rom.py words $(TARGET) 0x10d40 5 > $(OUT)/rom-services.txt
	$(PYTHON) tools/rom.py strings $(TARGET) --min-length 8 > $(OUT)/strings.txt
	$(PYTHON) tools/rom.py symbols $(TARGET) > $(OUT)/symbols.tsv
