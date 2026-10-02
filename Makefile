prog := iswebclientrunning-rs

cargo := $(shell command -v cargo 2> /dev/null)
cargo_v := $(shell cargo -V | cut -d ' ' -f 2)
rustup := $(shell command -v rustup 2> /dev/null)

check_cargo:
  ifndef cargo
    $(error cargo is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  else
	@echo "Make sure your cargo version is up to date! Current version is $(cargo_v)"
  endif

check_rustup:
  ifndef rustup
    $(error rustup is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  endif

update_rustup:
	rustup update

release: check_cargo
	cargo build --release
	cp target/release/$(prog) .
	@echo -e "[+] You can find \033[1;32m$(prog)\033[0m in your current folder."

debug: check_cargo
	cargo build
	cp target/debug/$(prog) ./$(prog)_debug
	@echo -e "[+] You can find \033[1;32m$(prog)_debug\033[0m in your current folder."

test: check_cargo
	cargo test

doc: check_cargo
	cargo doc --open --no-deps

install: check_cargo
	cargo install --path .
	@echo "[+] $(prog) installed!"

uninstall:
	@cargo uninstall $(prog)

clean:
	cargo clean

install_windows_deps: update_rustup
	@rustup install stable-x86_64-pc-windows-gnu --force-non-host
	@rustup target add x86_64-pc-windows-gnu
	@rustup install stable-i686-pc-windows-gnu --force-non-host
	@rustup target add i686-pc-windows-gnu

build_windows_x64:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(prog).exe .
	@echo -e "[+] You can find \033[1;32m$(prog).exe\033[0m in your current folder."

build_windows_x86:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target i686-pc-windows-gnu
	cp target/i686-pc-windows-gnu/release/$(prog).exe ./$(prog)_x86.exe
	@echo -e "[+] You can find \033[1;32m$(prog)_x86.exe\033[0m in your current folder."

windows: check_rustup install_windows_deps build_windows_x64
windows_x64: check_rustup install_windows_deps build_windows_x64
windows_x86: check_rustup install_windows_deps build_windows_x86

install_cross:
	@cargo install --version 0.2.5 cross

install_linux_musl_deps:
	@rustup install x86_64-unknown-linux-musl --force-non-host
	@rustup target add x86_64-unknown-linux-musl

build_linux_musl:
	cross build --target x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/$(prog) ./$(prog)_musl
	@echo -e "[+] You can find \033[1;32m$(prog)_musl\033[0m in your current folder."

linux_musl: check_rustup install_cross build_linux_musl

build_linux_aarch64:
	cross build --target aarch64-unknown-linux-gnu --release
	cp target/aarch64-unknown-linux-gnu/release/$(prog) ./$(prog)_aarch64
	@echo -e "[+] You can find \033[1;32m$(prog)_aarch64\033[0m in your current folder."

linux_aarch64: check_rustup install_cross build_linux_aarch64

build_linux_x86_64:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/$(prog) ./$(prog)_x86_64
	@echo -e "[+] You can find \033[1;32m$(prog)_x86_64\033[0m in your current folder."

linux_x86_64: check_rustup build_linux_x86_64

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets -- -D warnings

help:
	@echo ""
	@echo "Default:"
	@echo "usage: make install"
	@echo "usage: make uninstall"
	@echo "usage: make debug"
	@echo "usage: make release"
	@echo "usage: make test"
	@echo ""
	@echo "Static / cross:"
	@echo "usage: make windows        (x64)"
	@echo "usage: make windows_x86"
	@echo "usage: make linux_x86_64"
	@echo "usage: make linux_aarch64"
	@echo "usage: make linux_musl"
	@echo ""
