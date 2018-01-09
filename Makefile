all: main

main: main.p4
	p4c-bm2-ss -o p4c-out/bmv2/main.json \
		--p4runtime-file p4c-out/bmv2/main.p4info \
		--p4runtime-format text main.p4

clean:
	rm -rf p4c-out/bmv2/*.json
	rm -rf p4c-out/bmv2/*.p4info
