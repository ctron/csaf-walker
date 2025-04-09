semver:
    cargo semver-checks --features _crypto-nettle --only-explicit-features -p walker-common
    cargo semver-checks --features crypto-nettle --only-explicit-features -p csaf-walker
    cargo semver-checks --features crypto-nettle --only-explicit-features -p sbom-walker
    cargo semver-checks --features _crypto-nettle --only-explicit-features -p walker-extras
