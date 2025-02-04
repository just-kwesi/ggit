# Write Your Own Git (WYAG)

An educational Git implementation in Python that demonstrates core Git concepts and internal workings.

## Features

- Repository initialization
- Git object model implementation
- Basic repository operations
- Command-line interface mimicking Git

## Installation

```bash
git clone https://github.com/yourusername/wyag.git
cd wyag
chmod +x wyag
```

## Usage

```bash
./wyag init [path]      # Initialize repository
./wyag cat-file [SHA]   # Display object contents
./wyag hash-object      # Compute object hash
./wyag log              # Display commit history
```

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Requirements

```
wyag/
├── wyag              # Main executable
├── libwyag.py       # Core implementation
├── tests/           # Test suite
└── README.md        # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License
