.PHONY: build clean

# Extract binary to ./out/ via Docker buildx
build: clean
	docker buildx build --target export --output type=local,dest=out .

clean:
	rm -rf out
