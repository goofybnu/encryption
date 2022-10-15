<?php

namespace GoofyBNU\Encryption;

final class AES
{

    /**
     * Function to encrypt data
     * 
     * @param String $data                 Content to encript
     * @param String $encryptionKey        Encryption key
     * @param String $iv                   Initialization Vector
     * @param Int    $blockSize (optional) Encryption block size
     *                                     Default 256 
     *                                     Accepts 128, 192, 256
     * @param String $mode (optional)      Encryption mode
     *                                     Default 'CBC' 
     *                                     Accepts 'CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'
     * @param Int    $options (optional)   Encryption options
     *                                     Default 0
     *                                     Accepst 0, OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
     * 
     * @return String                      Encrypted data
     */
    static function encrypt($data, $encryptionKey, $iv, $blockSize = 256, $mode = 'CBC', $options = 0)
    {
        if (!self::validateParams($encryptionKey, $iv, $blockSize, $mode, $options)) throw new \Exception('Invlid params!');
        $method = self::returnMethodString($blockSize, $mode);
        return bin2hex(trim(openssl_encrypt($data, $method, $encryptionKey, $options, $iv)));
    }

    /**
     * Function to decrypt data
     * 
     * @param String $data                 Content to decript
     * @param String $encryptionKey        Encryption key
     * @param String $iv                   Initialization Vector
     * @param Int    $blockSize (optional) Encryption block size
     *                                     Default 256 
     *                                     Accepts 128, 192, 256
     * @param String $mode (optional)      Encryption mode
     *                                     Default 'CBC' 
     *                                     Accepts 'CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'
     * @param Int    $options (optional)   Encryption options
     *                                     Default 0
     *                                     Accepst 0, OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
     * 
     * @return String                      Decrypted data
     */
    public function decrypt($data, $encryptionKey, $iv, $blockSize = 256,  $mode = 'CBC', $options = 0)
    {
        if (!self::validateParams($encryptionKey, $iv, $blockSize, $mode, $options)) throw new \Exception('Invlid params!');
        $method = self::returnMethodString($blockSize, $mode);
        return trim(openssl_decrypt(hex2bin($data), $method, $encryptionKey, $options, $iv));
    }

    /**
     * Function to generate an encryption key string
     * 
     * @param Int     $length (optional) Length of encryption key
     *                                   Default 64
     * 
     * @return String Encription key string
     */
    static function generateEncryptionKey($length = 64)
    {
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }

    /**
     * Function to create an initialization vector string
     * 
     * @param Int    $blockSize (optional) Encryption block size
     *                                     Default 256 
     *                                     Accepts 128, 192, 256
     * @param String $mode (optional)      Encryption mode
     *                                     Default 'CBC' 
     *                                     Accepts 'CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'
     * 
     * @return String                      Initialization vector string
     */
    static function generateIV(Int $blockSize = 256, String $mode = 'CBC')
    {
        $method = self::returnMethodString((int)$blockSize, (string)$mode);
        $initializationVectorLength = openssl_cipher_iv_length($method) / 2;
        $initializationVectorRandomBytes = openssl_random_pseudo_bytes($initializationVectorLength);
        $initializationVectorHex = bin2hex($initializationVectorRandomBytes);
        return $initializationVectorHex;
    }

    /**
     * Function to validade parameter before encrypt/decrypt data
     * 
     * @param String $encryptionKey Encryption key
     * @param String $iv            Initialization vector
     * @param Int    $blockSize (optional) Encryption block size
     *                                     Default 256 
     *                                     Accepts 128, 192, 256
     * @param String $mode (optional)      Encryption mode
     *                                     Default 'CBC' 
     *                                     Accepts 'CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'
     * @param Int    $options (optional)   Encryption options
     *                                     Default 0
     *                                     Accepst 0, OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
     * 
     * @return bool
     */
    static function validateParams($encryptionKey, $iv, $blockSize, $mode, $options)
    {
        try {
            if (empty($encryptionKey)) throw new \Exception("Invalid encryption key");
            if (empty($iv)) throw new \Exception("Invalid initialization vector");
            if (strlen($iv) != 16) throw new \Exception("Invalid initialization vector");
            if (!in_array($blockSize, [128, 192, 256])) throw new \Exception("Invalid blockSize");
            if (!in_array($mode, ['CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'])) throw new \Exception("Invalid mode");
            if (!$blockSize == 192 and in_array($mode, ['CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'XTS'])) throw new \Exception("Invlid block size and mode combination");
            if (!in_array($options, [0, OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING])) throw new \Exception("Invalid option");
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Function to return string with encryption method
     * 
     * @param Int    $blockSize (optional) Encryption block size
     *                                     Default 256 
     *                                     Accepts 128, 192, 256
     * @param String $mode (optional)      Encryption mode
     *                                     Default 'CBC' 
     *                                     Accepts 'CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'OFB', 'XTS'
     * 
     * @return string                      String with encryption method
     */
    static function returnMethodString(Int $blockSize = 256, String $mode = 'CBC')
    {
        if (!in_array($blockSize, [128, 192, 256])) throw new \Exception("Invalid block size");
        if (!in_array($mode, ['CBC', 'CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'CFB', 'CFB1', 'CFB8', 'CTR', 'ECB', 'OFB', 'XTS'])) throw new \Exception("Invalid mode");
        if ($blockSize == 192 && in_array('', array('CBC-HMAC-SHA1', 'CBC-HMAC-SHA256', 'XTS'))) throw new \Exception('Invlid block size and mode combination!');
        return 'AES-' . $blockSize . '-' . $mode;
    }
}
