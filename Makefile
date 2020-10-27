default:
	cargo build --release

x86_64-unknown-linux-musl:
	cargo build --target $@ --release

armv7-unknown-linux-musleabihf:
	cross build --target $@ --release

arm-unknown-linux-musleabihf:
	cross build --target $@ --release

aarch64-unknown-linux-musl:
	cross build --target $@ --release