# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the current release branch receives security fixes.

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by email to the maintainers via the contact information
on the repository profile, or open a private security advisory through the
GitHub Security Advisories interface.

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including a minimal test case where possible
- The affected version(s)
- Any suggested remediation

You will receive an acknowledgement within 72 hours. We aim to issue a fix
within 14 days for confirmed vulnerabilities.

## Scope

This policy covers the ZOTE library source code. It does not cover:

- Third-party rule sets loaded by users of the library
- Applications built on top of ZOTE
- The build toolchain or dependencies of the CI environment

## Out of Scope

The following are not considered security vulnerabilities for the purposes
of this policy:

- Performance degradation without impact on correctness or confidentiality
- Issues requiring physical access to a system running ZOTE
- Issues in unreleased development branches

## Disclosure

Confirmed vulnerabilities will be disclosed publicly after a fix has been
released or after 90 days from the initial report, whichever comes first.
