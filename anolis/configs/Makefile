include Makefile.configs

ifeq ($(MAKELEVEL),0)
    $(error The config related target cannot be executed directly from the shell.)
endif

dist-defconfig:
	@sh scripts/generate_configs.sh generic-${DIST_ARCH}

dist-debug-defconfig:
	@sh scripts/generate_configs.sh debug-${DIST_ARCH}

dist-configs:
	@sh scripts/generate_configs.sh

dist-configs-update:
	@sh scripts/update_configs.sh

dist-configs-move:
	@sh scripts/move_configs.sh

dist-configs-import:
	@DO_IMPORT_CONFIGS=Y sh scripts/update_configs.sh

dist-configs-export:
	@sh scripts/export_configs.sh

dist-configs-check: dist-configs
	@sh examination/configs-check.sh

dist-configs-modify:
	@sh scripts/modify_config.sh

dist-configs-help:
	@echo ''
	@echo '--------------------------------'
	@echo 'Generate and update kernel configs'
	@echo '    dist-defconfig:        - generate anolis default config file of current ARCH, output to $${DIST_OUTPUT}'
	@echo '    dist-debug-defconfig:  - generate anolis debug default config file of current ARCH, output to $${DIST_OUTPUT}'
	@echo '    dist-configs:          - generate anolis config files to all arch, output to $${DIST_OUTPUT}'
	@echo '    dist-configs-update:   - refresh configs'
	@echo '    dist-configs-modify:   - modify the specified kconfig and refresh configs'
	@echo '    dist-configs-move:     - adjust the level of kconfig'
	@echo '    dist-configs-import:   - import legacy kconfig files, and split them into independent small files'
	@echo '    dist-configs-export:   - export all configs into a xlsx file'

export
