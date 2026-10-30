all: grub_base

grub_base grub_coverity: Containerfile
	podman build --target $@ --tag $@ .
