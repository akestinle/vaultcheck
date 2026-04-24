# vaultcheck

> CLI tool to audit and rotate secrets stored in HashiCorp Vault with policy diff reporting

---

## Installation

```bash
go install github.com/yourusername/vaultcheck@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/vaultcheck.git
cd vaultcheck
go build -o vaultcheck .
```

---

## Usage

Set your Vault address and token, then run an audit:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.yourtoken"

# Audit secrets and display policy diff
vaultcheck audit --path secret/myapp

# Rotate secrets at a given path
vaultcheck rotate --path secret/myapp --policy policy.hcl

# Compare current policy against a baseline
vaultcheck diff --baseline baseline.hcl --path auth/token
```

### Flags

| Flag | Description |
|------|-------------|
| `--path` | Vault secret path to target |
| `--policy` | Path to a local HCL policy file |
| `--baseline` | Baseline policy file for diff comparison |
| `--output` | Output format: `text`, `json` (default: `text`) |
| `--dry-run` | Preview changes without applying them |

---

## Requirements

- Go 1.21+
- HashiCorp Vault 1.12+
- A valid Vault token with appropriate permissions

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any significant changes.

---

## License

[MIT](LICENSE)