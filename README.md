# PHP AES Encrypter

[![Build Status](https://travis-ci.org/tebru/aes-encryption.svg?branch=master)](https://travis-ci.org/tebru/aes-encryption)
[![Coverage Status](https://coveralls.io/repos/tebru/aes-encryption/badge.svg?branch=master)](https://coveralls.io/r/tebru/aes-encryption?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/tebru/aes-encryption/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/tebru/aes-encryption/?branch=master)

A simple class to handle AES encryption of data

*DISCLAIMER: While the encryption/decryption has been tested, it has not been vetted by a security expert.  Use at your own risk.*

## Installation

Install using composer

```
composer require tebru/aes-encryption
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

### Encryption Methods

This library supports `aes128` `aes192` and `aes256`.  It uses `aes256` by default.

Use the `AesEnum` to use a different method.

```php
new AesEncrypter($key, AesEnum::METHOD_128);
```

### Encryption Strategy

Current supported PHP extensions are `mcrypt` and `openssl`.  This library requires mcrypt, but will use openssl instead
if it is available.

Upon constructing the encrypter, you may force the usage of one or the other.

```php
new AesEncrypter($key, AesEnum::METHOD_256, AesEncrypter::STRATEGY_MCRYPT);
```
