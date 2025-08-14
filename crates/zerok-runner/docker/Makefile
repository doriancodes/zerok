#
# Copyright 2023, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

work_root := ..

id := zerok-container
image_tag := $(id)
container_name := $(id)

uid := $(shell id -u)
gid := $(shell id -g)

rustup_channel = $(shell sed -nr 's,channel = "(.*)",\1,p' $(work_root)/rust-toolchain.toml)

.PHONY: none
none:

.PHONY: build
build:
	docker build \
		--build-arg UID=$(uid) --build-arg GID=$(gid) \
		--build-arg RUSTUP_CHANNEL=$(rustup_channel) \
		-t $(image_tag) .

.PHONY: run
run: build
	@docker rm -f $(container_name) >/dev/null 2>&1 || true
	docker run -d --name $(container_name) \
		-v $(abspath $(work_root)):/work:Z \
		--workdir /work \
		$(image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container_name) bash

.PHONY: rm-container
rm-container:
	for id in $$(docker ps -aq -f "name=^$(container_name)$$"); do \
		docker rm -f $$id; \
	done

.PHONY: test
test: build
	docker run --rm \
		--mount type=bind,readonly,src=$(abspath $(work_root)),dst=/work \
		-i $$([ -t 0 ] && echo -t) \
		$(image_tag) \
		make test BUILD=/tmp/build
