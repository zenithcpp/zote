# ZOTE

**zenithcpp Open Source Threat Engine**

[![License](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](LICENSE)
[![C++ ISO](https://img.shields.io/badge/C%2B%2B-ISO%2023-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Tests](https://img.shields.io/badge/Tests-126%20passing-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20%7C%20176%20techniques-red.svg)](https://attack.mitre.org)
[![Cppcheck](https://img.shields.io/badge/Cppcheck-clean-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen.svg)]()
[![Timestamped](https://img.shields.io/badge/Timestamped-Bitcoin%20blockchain-yellow.svg)](docs/ZOTE_v0.1.0.sha256.ots)

A C++23 library implementing a deterministic threat detection and correlation pipeline for SOC, XDR, and SIEM backends.

**Documentation:** [docs/README.md](docs/README.md)  
**Roadmap:** [docs/ROADMAP.md](docs/ROADMAP.md)  
**Contributing:** [docs/contribution/CONTRIBUTING.md](docs/contribution/CONTRIBUTING.md)  
**Security:** [docs/security/SECURITY.md](docs/security/SECURITY.md)

## Quick Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
