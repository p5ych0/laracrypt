# laracrypt
Obfuscation and Encryption functionality for Laravel

Simple usage example:

```php
app("encrypt.websafe")->encrypt($payload);

```

Note, that *SSL* encryptor requires an owner to be set. So you can have multiple keys determined by *owner*

```php
$ssl = app("encrypt.ssl")->setOwner("owner-id-kebab-cased");
$result = $ssl->encrypt($payload);
```
