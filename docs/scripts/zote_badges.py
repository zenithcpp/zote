#!/usr/bin/env python3
# zote_badges.py
# Run from ~/Desktop/ZOTE/
# Updates docs/README.md with professional badge header

import pathlib

p = pathlib.Path("docs/README.md")
content = p.read_text()

# Replace the existing header block (title through the first ---)
old_header = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**  
ISO C++23 · Zero external dependencies · Apache 2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

---'''

new_header = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**

[![License](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](../LICENSE)
[![C++ ISO](https://img.shields.io/badge/C%2B%2B-ISO%2023-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Header Standard](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg)]()
[![Tests](https://img.shields.io/badge/Tests-126%20passing-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20%7C%20176%20techniques-red.svg)](https://attack.mitre.org)
[![ICS](https://img.shields.io/badge/ICS%20ATT%26CK-87%20techniques-orange.svg)](https://attack.mitre.org/matrices/ics/)
[![Cppcheck](https://img.shields.io/badge/Cppcheck-clean-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen.svg)]()
[![Timestamped](https://img.shields.io/badge/Timestamped-Bitcoin%20blockchain-yellow.svg)](ZOTE_v0.1.0.sha256.ots)

---'''

content = content.replace(old_header, new_header, 1)
p.write_text(content, encoding="utf-8")
print("OK -- docs/README.md: badge header updated")

# Also update root README.md
p2 = pathlib.Path("README.md")
content2 = p2.read_text()

old_root = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**  
ISO C++23 · Zero external dependencies · Apache 2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)'''

new_root = '''\
# ZOTE

**zenithcpp Open Source Threat Engine**

[![License](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](LICENSE)
[![C++ ISO](https://img.shields.io/badge/C%2B%2B-ISO%2023-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Tests](https://img.shields.io/badge/Tests-126%20passing-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20%7C%20176%20techniques-red.svg)](https://attack.mitre.org)
[![Cppcheck](https://img.shields.io/badge/Cppcheck-clean-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen.svg)]()
[![Timestamped](https://img.shields.io/badge/Timestamped-Bitcoin%20blockchain-yellow.svg)](docs/ZOTE_v0.1.0.sha256.ots)'''

content2 = content2.replace(old_root, new_root, 1)
p2.write_text(content2, encoding="utf-8")
print("OK -- README.md (root): badge header updated")

# Print what the badges will look like
print("")
print("BADGES:")
print("  Apache 2.0          [green]")
print("  C++ ISO 23          [blue]")
print("  Standard C++23      [blue]")
print("  Tests 126 passing   [green]")
print("  MITRE ATT&CK v14    [red]    176 techniques")
print("  ICS ATT&CK          [orange] 87 techniques")
print("  Cppcheck clean      [green]")
print("  Dependencies none   [green]")
print("  Timestamped Bitcoin [yellow]")
