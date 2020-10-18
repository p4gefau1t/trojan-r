default: x86_64-unknown-linux-musl

x86_64-unknown-linux-musl:
	cargo build --target $@ --release
	strip target/$@/release/trojan-r

armv7-unknown-linux-musleabihf:
	cross build --target $@ --release

arm-unknown-linux-musleabihf:
	cross build --target $@ --release

aarch64-unknown-linux-musl:
	cross build --target $@ --release