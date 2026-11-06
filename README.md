# RSA Public-Key Encryption and Signature Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-orange.svg)](https://creativecommons.org/licenses/by/4.0/)

Linear game for [CyberRangeCZ Platform](https://docs.platform.cyberrange.cz/).
Students program RSA in C with the OpenSSL BIGNUM library.

## Game Levels Summary

- connect to sandbox and open the lab directory `~/tp`
- T1: derive the private key `d` from `p`, `q`, `e`
- T2: encrypt a message
- T3: decrypt a message
- T4: sign a message
- T5: verify a signature (valid, then corrupted)
- T6: manually verify an X.509 certificate

## Topology summary

| Host     | Image             | Flavor         |
| -------- | ----------------- | -------------- |
| attacker | kali              | standard.small |
| router   | debian-12-x86_64  | standard.small |

## License

This repository uses a dual licensing approach:

- The code (Ansible and custom code) is licensed under the terms of the MIT License (https://opensource.org/license/mit).
- The game design is licensed under a Creative Commons Attribution 4.0 International License (CC BY 4.0).

**Attribution:**

Repository structure and game format based on:
library-junior-hacker (https://github.com/cyberrangecz/library-junior-hacker),
itself based on junior-hacker (https://gitlab.ics.muni.cz/muni-kypo-trainings/games/junior-hacker),
Cybersecurity Laboratory, Faculty of Informatics, Masaryk University
(leading author: Miriam Gáliková; contributors: Valdemar Švábenský, Jan Vykopal).

Lab tasks based on "RSA Public-Key Encryption and Signature Lab" from SEED Labs,
Copyright © 2018 Wenliang Du (https://seedsecuritylabs.org), free to use for
non-commercial educational purposes.
