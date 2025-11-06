# Azul Plugin Malcarve

Plugin to carve and feature obfuscated content from files.

## Development Installation

To install azul-plugin-malcarve for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
azul-plugin-malcarve malware.file
```

Example Output:

```bash
----- Malcarve results -----
OK

Output features:
       embedded_type: pe
                      pe
                      pe
                      url
                      useragent
                      zip
          user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36
  obfuscation_scheme: base64
                      base64.deflate
        embedded_url: http://ip-api.com/json/
                      base64.deflate - http://www.w3.org/2001/XMLSchema-instance

Generated child entities (4):
  {'offset': '0x000a', 'action': 'deobfuscated', 'scheme': 'base64.deflate'} <binary: 272e64291748fa8be01109faa46c0ea919bf4baf4924177ea6ac2ee0574f1c1a>
    content: 26112 bytes
  {'offset': '0x000a', 'action': 'deobfuscated', 'scheme': 'base64.deflate'} <binary: 0421fab0c9260a7fe3361361581d84c000ed3057b9587eb4a97b6f5dc284a7af>
    content: 18944 bytes
  {'offset': '0x000a', 'action': 'deobfuscated', 'scheme': 'base64.deflate'} <binary: d65a3033e440575a7d32f4399176e0cdb1b7e4efa108452fcdde658e90722653>
    content: 19968 bytes
  {'offset': '0x18de9', 'action': 'deobfuscated', 'scheme': 'base64'} <binary: 6f3cf374a1aa961be87dde5aaeb1706d95cdcadbd1a4c961363e5ff33fab168d>
    content: 54696 bytes

Feature key:
  embedded_url:  URL found embedded in content
  embedded_type:  Payload type found embedded in content
  user_agent:  User-Agent found embedded in content
  obfuscation_scheme:  Obfuscation/encoding of embedded content

```

Automated usage in system:

```bash
azul-plugin-malcarve --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
