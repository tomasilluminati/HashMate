
![Banner](./logo/big-banner.png)

HashMate is a versatile toolkit for performing various hash operations efficiently.

![License](https://img.shields.io/badge/License-MIT-red.svg)
![Version](https://img.shields.io/badge/Version-1.0-brightgreen)
![Python Version](https://img.shields.io/badge/python-3.11-blue)
![Algorithms](https://img.shields.io/badge/ID_Algorithms-304-yellow)
![Regular Expressions](https://img.shields.io/badge/Regular_Expressions-298-green)
![Calculable Algorithms](https://img.shields.io/badge/Calculable_Algorithms-21-cyan)


## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Features](#features)
- [Modes](#modes)
   -   [calculate](#calculate)
   -   [id-hash](#id-hash)
   -   [compare](#id-hash)
   -   [dehash](#id-hash)
- [Options](#options)
   - [Options for Calculate](#options-for-calculate)
   - [Options for id-hash](#options-for-id-hash)
   - [Options for compare](#options-for-compare)
   - [Options for dehash](#options-for-dehash)
- [Calculate and dehash Algorithms List](#calculate-and-dehash-algorithms-list)
- [Identifiable Algorithms List](#algotrith-list-id-hash)
- [Extras](#extras)
- [Contributing](#contributing)
- [License](#license)

## Introduction

HashMate provides functionalities for calculating, identifying, comparing, and dehashing hashes using different algorithms. It offers flexibility and ease of use in hash-related tasks.

## Features

- **Calculation Mode**: Calculate hash values for strings or files.
- **Identification Mode**: Identify the algorithm used to generate a hash.
- **Compare Mode**: Compare two hash values.
- **Dehash Mode**: Attempt to reverse hash values using a provided wordlist.
- **Algorithm List**: View a list of supported hash algorithms.
- **Exporting**: Export results to files.
- **Multi-threading**: Utilize multiple threads for faster dehashing.

## Installation

To install HashMate, simply clone this repository and ensure you have Python 3.x installed.

```sh
git clone https://github.com/yourusername/hashmate.git
```


Then run the command with the parameters to use it.

```sh
python3 hashmate.py <mode> <parameters>
```


## Modes

- `--calculate`: Calculation Mode
- `--id-hash`: Identification Mode
- `--compare`: Compare Mode
- `--dehash`: DeHash Mode
- `--algorithm-list`: Show a list of allowed algorithms to calculate and dehash
- `--man`: Manual

## calculate

Calculate hash values for files using various algorithms. Specify the file path using the --file option, or the directory path using --dir, you can also select whether you want the type of algorithm (--algorithm) to calculate and you can export the result of the file or files with -oN

Example:

```sh
python3 hashmate.py --calculate --string 'Hello World' -oN ./myfile.txt
```

```sh 
python3 hashmate.py --calculate --file ./myfile.txt --algorithm sha256 -oN ./myfile.txt
```

```sh
python3 hashmate.py --calculate --dir ./my/path/to/dir/ -oN ./myfile.txt
```


## id-hash
Identification Mode allows HashMate to determine the algorithm used to generate a hash value. 
This mode helps users identify unknown hash types, ensuring compatibility with the appropriate hashing algorithms.

Example:

```sh
python3 hashmate.py --id-hash --hash b10a8db164e0754105b7a99be72e3fe5 -oN ./myfile.txt
```

## compare

Compare two hash values to check similarity. Use the --h1 and --h2 options to provide hash values for comparison. --oN is not implemented for --compare

*Example:*

```sh
python3 hashmate.py --compare -h1 b10a8db164e0754105b7a99be72e3fe5 --h2 b10a8db164e0754105b7a99be72e3fe5 -oN ./myfile.txt
```

## dehash
Dehash Mode attempts to reverse the hashing process by searching for the original plaintext value of a hash using a provided wordlist. This mode is beneficial for recovering passwords, uncovering sensitive information, and testing the strength of hash functions.

```sh
python3 hashmate.py --dehash -hash 'b10a8db164e0754105b7a99be72e3fe5' -oN ./myfile.txt
```

## Options

### Options for calculate

- `--string`: String to work
- `--file`: Path to the file.
- `--dir`: Path to the directory.
- `--algorithm`: Hash algorithm to use (Default SHA256).
- `-oN`: Export the file (Name with extension).
- `--block-size`: Block Size.

### Options for id-hash

- `--hash`: Hash to work.
- `-oN`: Export the file (Name with extension).

### Options for compare

- `--h1`: Hash 1 for comparison.
- `--h2`: Hash 2 for comparison.
- `-oN`: Export the file (Name with extension).

### Options for dehash

- `--hash`: Hash to work.
- `-t THREADS`: Number of threads to dehash (Default 4).
- `--wordlist`: Path to the wordlist (Only .txt files).

## Calculate and dehash algorithms List

The following list specifies those algorithms that can be calculated and hashed. We are working to add more

- MD5 (md5)
- MD5-SHA1 (md5-sha1)
- MD4 (md4)
- Double-MD5 (doublemd5)
- SHA1 (sha1)
- SHA224 (sha224)
- SHA256 (sha256)
- SHA384 (sha384)
- SHA512 (sha512)
- SHA512-224 (sha512-224)
- SHA512-256 (sha512-256)
- SHA3-224 (sha3-224)
- SHA3-256 (sha3-256)
- SHA3-384 (sha3-384)
- SHA3-512 (sha3-512)
- Whirlpool (whirlpool)
- CRC32 (crc32)
- Blake2s (blake2s)
- Blake2b (blake2b)
- RIPEMD-160 (ripemd160)
- SM3 (sm3)

## Algotrith List (id-hash)

This files provides various types of hashes used in systems and applications for securing sensitive information, primarily passwords. It lists algorithms like MD5, SHA-1, bcrypt, and many others

**FULL LIST (NAMES ONLY):** [ALGORITHMS](others/Identifiable_Algorithms.md) **(304 Algorithms)**

**RE & ALGORITHMS FULL LIST:** [RE & ALGORITHMS](lib/hash_lib.py) **(298 Regular Expressions)**

## Extras!!

In addition to the core functionality, HashMate provides supplementary resources aimed at enhancing the user experience. These extras are conveniently located within the [others](others) directory:

- **Wordlist for Testing:** Included within this directory is a copy of 3 wordlists *(big, medium, little)* designed for testing purposes, based on the renowned rockyou.txt dictionary. This wordlists serves as a valuable asset for comprehensive testing scenarios in dehash mode, enabling users to assess the robustness and effectiveness of HashMate.

- **Hash Identification List:** A meticulously curated Markdown file (Identifiable_Algorithms.md) is available, listing all identifiable hashes by the ID-hash mode. This resource simplifies the process of searching for hashes within the HASH_LIB, as it is a compilation of all available identifiable hashes.

Moreover, within the [lib](lib) directory, users can find:

- **Python Script for Generating Identifiable_Algorithms.md:** A Python script is provided, carefully designed to generate the aforementioned list of identifiable hashes. This script embodies the commitment to user convenience and efficiency, enabling collaboration with the project.

Finally, within the logos directory, users can find:

- **Logos:** variations of the HashMate logo for promotional, press, citation, etc., purposes.

These supplementary components allow for a better user experience and ease of collaboration with the project.

## Contributing 

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request. Feel free to add more hashes to the [list](lib/hash_lib.py) or contribute regular expressions for matching IDs. Check if the hash you want to add is in the [list](others/Identifiable_Algorithms.md). Let's collaborate to enhance this project together! 🚀

## License

**Copyright © 2024 Tomás Illuminati**

*This project is licensed under the [GPL-3.0 license](LICENSE).*


