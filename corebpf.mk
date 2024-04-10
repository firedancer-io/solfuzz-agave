.PHONY: clean

AddressLookupTable: programs
	mkdir -p programs
	@if [ -d "programs/address-lookup-table" ]; then \
		echo "Updating address lookup table..."; \
		(cd programs/address-lookup-table && git fetch && git pull); \
	else \
		echo "Cloning address lookup table..."; \
		git clone https://github.com/solana-program/address-lookup-table programs/address-lookup-table; \
	fi
	cargo build-sbf --manifest-path=programs/address-lookup-table/program/Cargo.toml --sbf-out-dir programs
	mv programs/solana_address_lookup_table_program.so programs/program.so

Config: programs
	mkdir -p programs
	@if [ -d "programs/config" ]; then \
		echo "Updating config..."; \
		(cd programs/config && git fetch && git pull); \
	else \
		echo "Cloning config..."; \
		git clone https://github.com/solana-program/config programs/config; \
	fi
	cargo build-sbf --manifest-path=programs/config/program/Cargo.toml --sbf-out-dir programs
	mv programs/solana_config_program.so programs/program.so

clean:
	rm -rf programs
