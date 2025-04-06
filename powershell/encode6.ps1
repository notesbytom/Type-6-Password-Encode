# Based on https://github.com/CiscoDevNet/Type-6-Password-Encode/blob/main/encode6.py
# Which was: "Copyright (c) 2018 Cisco Systems. All rights reserved."

$TYPE6_SALT_LEN = 8
$TYPE6_MAC_LEN = 4
$NO_PAD = [Security.Cryptography.PaddingMode]::None

function base41_decode($three_symbols) {
    if($three_symbols.Length -ne 3) { throw "Three Symbols Length Must Be 3!" }
    $INT_CAP_A = [int]'A'[0] # Int Value of Character (A)
    $x = [int]$three_symbols[0] - $INT_CAP_A
    $y = [int]$three_symbols[1] - $INT_CAP_A
    $z = [int]$three_symbols[2] - $INT_CAP_A
    [uint16]$num16 = ($x * 41 * 41) + ($y * 41) + $z # 16 bit Integer
    [Byte[]]$two_bytes = [System.BitConverter]::GetBytes($num16)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($two_bytes) }
    return $two_bytes # [Byte[]]
}

function base41_encode([Byte[]]$two_bytes) {
    if($two_bytes.Length -ne 2) { throw "Two Bytes Length Must Be 2!"}
    $b41_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_``abcdefghi"
    if([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($two_bytes) }
    $number = [BitConverter]::ToUInt16($two_bytes,0)
    $z = -1 # Below equivalent of z = number % 41
    $number = [Math]::DivRem($number,41,[ref]$z) # number //= 41
    $y = -1 # Below equivalent of y = number % 41
    $x = [Math]::DivRem($number,41,[ref]$y) # number //= 41
    return $b41_chars[$x] + $b41_chars[$y] + $b41_chars[$z] # [String]
}

function b41_decode($encoded_string) {
    if($encoded_string.Length % 3 -ne 0) { throw "Encoded String Length Must Be Divisible by 3!" }
    $decoded_bytes = [Byte[]]::new(0) # Empty Byte Array
    for ($i=0; $i -lt $encoded_string.Length; $i += 3) {
        $chunk = $encoded_string[$i..($i + 3-1)]
        $decoded_bytes += base41_decode -three_symbols $chunk
    }
    # Adjust Last Index to Remove Padding
    $last_index = $decoded_bytes.Length -1 - $(if ($decoded_bytes[-1] -eq 0) { 1 } else { 2 })
    return $decoded_bytes[0..$last_index] # [Byte[]]
}

function b41_encode([Byte[]]$binary) {
    $encoded_str = ""
    for ($i=0; $i -lt $binary.Length; $i += 2) {
        $val = $binary[$i..($i+2-1)]
        if ($val.Length -eq 2) {
            $encoded_str += base41_encode -two_bytes $val
        }
    }
    $pad = if ($binary.Length % 2 -ne 0) { $binary[-1], [Byte]0 } else { [Byte[]](0,1) }
    $encoded_str += base41_encode -two_bytes $pad
    return $encoded_str
}

function password_mac_verify($encrypted_keystring, $master_key <# str #>) {
    $a = b41_decode $encrypted_keystring
    $salt = $a[0..($TYPE6_SALT_LEN-1)]
    $encrypted_pw = $a[$TYPE6_SALT_LEN..($a.Length-1-$TYPE6_MAC_LEN)]
    $mac = $a[($a.Length-$TYPE6_MAC_LEN)..($a.Length-1)]

    $calculated_mac = password_mac_generate -encrypted_key_bytes $encrypted_pw -master_key $master_key -salt $salt
    if (-not [Linq.Enumerable]::SequenceEqual([Byte[]]$calculated_mac, [Byte[]]$mac)) { 
        throw "Password Validation failed"
    }
}

function password_mac_generate([Byte[]]$encrypted_key_bytes, $master_key <# str #>, [Byte[]]$salt) {
    $password = [Text.Encoding]::UTF8.GetBytes($master_key)
    $password_md5_digest = [Security.Cryptography.MD5]::Create().ComputeHash($password)
    $aes = [Security.Cryptography.AES]::Create()
    $aes.KeySize = 128 
    $aes.Key = $password_md5_digest
    $auth_key = $aes.EncryptEcb($salt + [Byte[]](0,0,0,0,0,0,0,0),$NO_PAD)
    $hmaccer = [Security.Cryptography.HMACSHA1]::new()
    $hmaccer.Key = $auth_key
    $hash_bytes = $hmaccer.ComputeHash($encrypted_key_bytes)
    return $hash_bytes[0..($TYPE6_MAC_LEN-1)] # Truncate to TYPE6_MAC_LEN
}

function transform_bytes($in_bytes, $salt_bytes, $key_str) {
    $key_bytes = [Text.Encoding]::UTF8.GetBytes($master_key)
    $aes = [Security.Cryptography.AES]::Create()
    $aes.KeySize = 128 
    $aes.Key = [Security.Cryptography.MD5]::Create().ComputeHash($key_bytes)
    $aes.Key = $aes.EncryptEcb($salt_bytes + [Byte[]](0,0,0,0,0,0,0,1), $NO_PAD)
    $out_bytes = [Byte[]]::new(0) # Empty Byte Array
    for ($x=0; $x -lt $in_bytes.Length; ++$x) {
        $x_mod_16 = -1 # get by reference below
        $x_div_16 = [Math]::DivRem($x,16,[ref]$x_mod_16)
        if ($x_mod_16 -eq 0) { # New Key for every block size
            $block_key = [Byte[]]::new(16) # Sixteen Zero Bytes (128 bits)
            $block_key[3] = $x_div_16 # x // 16
            $block_key = $aes.EncryptEcb($block_key,$NO_PAD)
        }
        $x_byte = $in_bytes[$x]
        $out_bytes += $x_byte -bxor $block_key[$x_mod_16]
    }
    return $out_bytes
}

function encrypt_type_6_password([string]$cleartext_pw, [string]$master_key) {
    $salt = [Byte[]]::new($TYPE6_SALT_LEN)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $clear_bytes = [Text.Encoding]::UTF8.GetBytes($cleartext_pw)
    $out_bytes = transform_bytes -in_bytes $clear_bytes -salt_bytes $salt -key_str $master_key
    $mac = password_mac_generate -encrypted_key_bytes $out_bytes -master_key $master_key -salt $salt
    return b41_encode -binary ($salt + $out_bytes + $mac) # [String]
}

function decrypt_type_6_password([string]$encrypted_keystring, [string]$master_key) {
    password_mac_verify -encrypted_keystring $encrypted_keystring -master_key $master_key
    # The encrypted_keystring is base41(SALT + Encrypted Key + MAC)
    $a = b41_decode $encrypted_keystring
    $salt = $a[0..($TYPE6_SALT_LEN-1)]
    $encrypted_pw = $a[$TYPE6_SALT_LEN..($a.Length-1-$TYPE6_MAC_LEN)]
    $out_bytes = transform_bytes -in_bytes $encrypted_pw -salt_bytes $salt -key_str $master_key
    return [Text.Encoding]::UTF8.GetString($out_bytes).TrimEnd([char]0)
}

###### Example usage ######

# This was a password (Cisco123) generated on a router with the master_key also set to Cisco123
$enc_pass = "fe_a``iJYE\DZYJhDhTP[``MYaTgRH_MAAB"
$master_key = "Cisco123"
$decrypted_pass = decrypt_type_6_password -master_key $master_key -encrypted_keystring $enc_pass
Write-Host "$enc_pass decrypts to '$decrypted_pass'"

# Test generating and decrypting
$password_to_be_encrypted = "1234567890123456ABCDabcd" # "ABCD"
$encrypted_password = encrypt_type_6_password -cleartext_pw $password_to_be_encrypted -master_key $master_key
$decrypted_generated_password = decrypt_type_6_password -encrypted_keystring $encrypted_password -master_key $master_key
Write-Host "'$password_to_be_encrypted' encrypts to '$encrypted_password' decrypts to '$decrypted_generated_password'"
