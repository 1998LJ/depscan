# depscan — Multi-ecosystem Dependency Scanner

Scan dependencies across multiple ecosystems with typosquat detection.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan current directory
depscan scan .

# Scan with typosquat detection
depscan scan /path/to/project --typosquat

# List all dependencies
depscan list-deps .

# Check a specific package
depscan check requests 2.28.0

# JSON output
depscan scan . --json-output

# Show supported ecosystems
depscan info
```

## Features

- **Multi-ecosystem**: Cargo, npm, PyPI, Go
- **Typosquat detection**: Levenshtein-based similarity check
- **JSON output**: For automation and CI integration
- **Rich terminal output**: Tables, panels, progress bars

## Supported Formats

| Ecosystem | File |
|-----------|------|
| Cargo | Cargo.lock |
| npm | package-lock.json |
| PyPI | requirements.txt, poetry.lock |
| Go | go.mod |

## License

MIT
