.PHONY: build clean

# Extract binary to ./out/ via Docker buildx
build:
	docker buildx build --output type=local,dest=out .

clean:
	rm -rf out
