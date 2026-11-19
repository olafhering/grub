.PHONY: all grub_base grub_coverity run push

# Define registry and upstream image name. TAG must match the image
# referenced in .gitlab-ci/yml/global.yml, e.g. make push TAG=2026-11-19.1
DEBIAN_TRIXIE=debian-trixie
QUAY_GRUB_REPO=quay.io/grub/$(DEBIAN_TRIXIE)-grub:$(TAG)

all: grub_base

grub_base grub_coverity: Containerfile
	podman build --target $@ --tag $@ .

run: grub_base
	podman run -it --device /dev/net/tun --cap-add NET_ADMIN $^

# Notice that the grub_coverity is the dependency in this case because
# ultimately the CI image used coverity for weekly scans.
push: grub_coverity
	@test -n "$(TAG)" || { echo "TAG is required, e.g. make push TAG=YYYY-MM-DD.N" >&2; exit 1; }
	podman tag $^ $(QUAY_GRUB_REPO) && podman push $(QUAY_GRUB_REPO)
