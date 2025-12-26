DIR = $(shell pwd)/src

all: build run
.PHONY: clear build fuz

build:
	docker build --no-cache -t my-afl-project:latest .

run:
	docker run \
	  --network host --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=NET_BIND_SERVICE \
	  -it \
      --name my-afl \
      -v $(shell pwd)/src:/app/src \
      my-afl-project:latest /bin/bash
cp:
	docker cp $(DIR) my-afl:/app
fuz:
	afl-fuzz -i seeds -o build/out -- ./build/connman_fuz
exec:
	docker exec -it my-afl /bin/bash

start:
	docker start -i my-afl
stop:
	docker stop my-afl