# Encryption

Simple gerenciador de conexões SSH em PHP utilizando a lib SSH2

## Instalação
Para instalar esta dependência bas executar o comando abaixo:
```shell
composer require goofybnu/encryption
```

---

## Modos e Tamanhos de blocos aceitos

Modos que aceitam os tamanhos de blocos 128, 192 e 256
- CBC
- CFB
- CFB1
- CFB8
- CTR
- OFB

Modos que aceitam os tamanhos de blocos 128 e 256
- CBC-HMAC-SHA1
- CBC-HMAC-SHA256
- XTS

---

## Exemplo de utilização para criptografar
```php
<?php

require __DIR__ . '/vendor/autoload.php';

use GoofyBNU\Encryption\AES;

$data = 'Variável com os dados a serem criptografados';
$encryptionKey = '61b0581de759f5dbc4e5518773d3b89344597995db5762e1e1b33cb4e82c5b3d';
$iv = '122d8944030b53dd';
$encryptedData = AES::encrypt($data, $encryptionKey, $iv);
echo $encryptedData;

```

---

## Exemplo de utilização para descriptografar
```php
<?php

require __DIR__ . '/vendor/autoload.php';

use GoofyBNU\Encryption\AES;

$data = '6378504464733569613979684a305555723046784f687a556b43704c38326151792b38495a4c636362396f706565636f33776858534f41454368686534445763';
$encryptionKey = '61b0581de759f5dbc4e5518773d3b89344597995db5762e1e1b33cb4e82c5b3d';
$iv = '122d8944030b53dd';
$decryptedData = AES::encrypt($dataEncrypted, $encryptionKey, $iv);
echo $decryptedData;

```

---

## Função para gerar chave de criptografia
```php
<?php

require __DIR__ . '/vendor/autoload.php';

use GoofyBNU\Encryption\AES;

$encryptionKey = generateEncryptionKey();
echo $encryptionKey;

```

---

## Função para gerar vetor de inicialização
```php
<?php

require __DIR__ . '/vendor/autoload.php';

use GoofyBNU\Encryption\AES;

$blockSize = 256;
$mode = 'CBC';
$iv = generateIV($blockSize, $mode);
echo $iv;

```

---

## Requisitos
- Necessário PHP 7.0 ou superior