.PHONY: all grub_base grub_coverity run

all: grub_base

grub_base grub_coverity: Containerfile
	podman build --target $@ --tag $@ .

run: grub_base
	podman run -it --device /dev/net/tun --cap-add NET_ADMIN $^
