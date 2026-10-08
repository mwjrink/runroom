# List commands; no installation or config replacement by default.
default:
    @just --list

# Native CPU and opt-level=3 defaults come from .cargo/config.toml.
build:
    cargo build --release

# Install through Cargo only; leave config and systemd untouched.
install:
    cargo install --path .

# Reinstall the current checkout.
update: install

# Validate config and the live daemon using the current checkout.
verify:
    cargo run --release -- verify --config "${XDG_CONFIG_HOME:-$HOME/.config}/runroom/config.toml"

# Explicitly overwrite config from the template; no build/install or daemon restart.
replace-config:
    #!/usr/bin/env python3
    import os
    from pathlib import Path

    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "runroom/config.toml"
    text = Path("config.toml.in").read_text().replace("@UID@", str(os.getuid()))
    config.parent.mkdir(parents=True, exist_ok=True)
    config.touch(mode=0o600, exist_ok=True)
    config.chmod(0o600)
    config.write_text(text)

# Run the permanent regression suite.
test:
    cargo test --all-targets

# Check formatting and lint all targets.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings

# Format Rust sources.
fmt:
    cargo fmt --all
