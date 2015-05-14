# PHP AES Encrypter

[![Build Status](https://travis-ci.org/tebru/aes-encryption.svg?branch=master)](https://travis-ci.org/tebru/aes-encryption)
[![Coverage Status](https://coveralls.io/repos/tebru/aes-encryption/badge.svg?branch=master)](https://coveralls.io/r/tebru/aes-encryption?branch=master)

A simple class to handle AES encryption of data

*DISCLAIMER: While the encryption/decryption has been tested, it has not been vetted by a security expert.  Use at your own risk.*

## Installation

Install using composer

```
composer require tebru/aes-encryption:0.1.*
```

## Usage

Simply instantiate the encrypter class with a key and use the `encrypt`/`decrypt` methods

```php
<?php

$encrypter = new AesEncrypter($key);
$encrypted = $encrypter->encrypt('My secure data');
$decrypted = $encrypter->decrypt($encrypted);
```

The encrypt method is able to handle encryption of any kind of data because it serializes the data first.

### Encryption Block Sizes

Use the `CipherEnum` to pass in a block size to determine with Rijndael cipher to use.  Allowed values are `128`, `192`, and `256`.

```php
new AesEncrypter($key, CipherEnum::BLOCK_SIZE_256);
```

### Encryption Modes

Use the `ModeEnum` to pass in an encryption mode.  Allowed values are `cbc`, `cfb`, `ecb`, `nofb`, and `ofb`.

```php
new AesEncrypter($key, CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_ECB);
```
