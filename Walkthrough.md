## keyskeyskees - Crypto Challenge -Walkthrough

#### Flag Format

Flag format - flag_{md5sum}

Eg. flag_{0d599f0ec05c3bda8c3b8a68c32a1b47}

#### Starting Files

* block-aa
* block-ab
* block-ac
* block-ad
* block-ae
* dootdoot.key.jpeg
* for_later_wink_wink
* openssl_notes
* sha256sum.txt

###### block-a*

```bash
$ file block-a*
block-aa: LUKS encrypted file, ver 2 [, , sha256] UUID: 871dd3d3-dfad-450f-95c4-2fdfa093f031
block-ab: data
block-ac: data
block-ad: data
block-ae: data

$ head -n 2 block-aa
LUKS@sha256
           V[4AsD?xa+/m;O{4Ί [
.ຫY$Xe  k871dd3d3-dfad-450f-95c4-2fdfa093f031B\SoyCױ1t"(
|x{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":7,"memory":1048576,"cpus":4,"salt":"eriwhaSidMHXaxZUxl6fLCfyHYK01nCWzbVHEhwXPVc="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":148439,"salt":"rq8gOWLddtju/Zoz/TUAgrC5izY4nvNd4PUwtbRCrtw=","digest":"G9A3oufYjfnU0ipNtN6qkFP1DRkSBQ2YFK0cKVdpIUM="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}SKUL@sha256,g>"JBOq_6#$/<
```

###### dootdoot.key.jpeg

```bash
$ file dootdoot.key.jpeg  
dootdoot.key.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 82", baseline, precision 8, 475x458, components 3
```

###### for_later_wink_wink

```bash
$ file for_later_wink_wink
for_later_wink_wink: PEM RSA private key
```

###### openssl_notes

```bash
$ cat openssl_notes           
# openssl enc -list
Supported ciphers:
-blowfish

# openssl dgst -list
Supported digests:
-sha512

# openssl -pbkdf2
PBKDF2 password-based key derivation function

# openssl -iter 5
Use a given number of iterations on the password in deriving the encryption key.
High values increase the time required to brute-force the resulting file.
This option enables the use of PBKDF2 algorithm to derive the key.
```



#### LUKS Volume

Linux Unified Key Setup (LUKS) is a disk encryption specification released in 2004. The default cipher used for LUKS is aes-xts-plain64 and the default key size is 512 bits.

The files block-a* are a LUKS encrypted file that has been split into 5 equal parts. Joining the files together can be achieved with cat.

```bash
$ cat block-a* > block.img
```

There is no password to unlock the file, however there is dootdoot.KEY.jpeg. Can use the Jpeg as a key file to decrypt and mount the block device. Inside is a file 'Password1'

```bash
$ sudo cryptsetup luksOpen ./block.img unlocked-block --key-file ./dootdoot.key.jpeg
$ mkdir unlocked-block
$ sudo mount /dev/mapper/unlocked-block unlocked-block
```



#### Ansible Vault

Ansible is a configuration management tool. While working with Ansible, you can create various playbooks, inventory files, variable files, etc. Some of the files contain sensitive and important data like usernames and passwords. Ansible provides a feature named Ansible Vault that prevents this data from being exposed.

The file 'Password1' is an Ansible vault encrypted YAML file. Can decrypt and view/edit the contents using the ansible-vault tool and the password "Password1".

```bash
$ head -n 2 Password1
$ANSIBLE_VAULT;1.1;AES256
38383363363534313532313564306337313932336363333733326135333638323231343732646431

$ ansible-vault view ./Password1
```

Inside the decrypted YAML is two variables, 'key' and 'encrypted_blob'. These are PGP ASCII-Armored files.

#### GPG/PGP

GnuPG is a complete and free implementation of the OpenPGP standard as defined by RFC4880 (also known as PGP). GnuPG allows you to encrypt and sign your data and communications

After extracting both the key and the encrypted blob from the YAML, the GPG private key needs to be imported and the message decrypted. The result appears to be yet another encrypted/encoded text blob.

```bash
$ gpg --import key.asc.gpg
gpg: key 900206CF194F243A: "Jackery Fibson (Encrypt All the Things) <jackery.fibson@403.mail.com>" not changed
gpg: key 900206CF194F243A: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1

$ gpg -d encrypted_blob.asc.gpg > decrypted_blob
$ head -n 2 encrypted_blob                                             
U2FsdGVkX1+Y4QOmCsrCN2Tcs0QKSfJeb7AAIxCQ5vnolqnPJ2CuDCcMPnU1dcUe6SmluvRypy98
u3lU+W9SSpOtV0RLLCh0FSPbUB4BMiS0kH0keVTpnp0C7VEjYKikwyk3isDmVWISH7Wu00ipTQqF
```



#### Base64 Encoded OpenSSL Encrypted File

OpenSSL is a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols

The '=' character at the end of the decrypted_blob hints that this is Base64 encoded. Decoding reveals an OpenSSL encrypted file. This can then be decrypted using the file 'for_later_wink_wink'

The OpenSSL notes are important for this step. They detail the cipher, message-digest and number of iterations.

```bash
$ tail -n 2 encrypted_blob
/HHOv0tDvVco/hxItjF9pIaLZMnUM+2Mx36ESLz9JKp5fPtS0o6VBt1ndGbKA0mNY0MG6h5W34+m
2besQLjLLe4P9z+xehTrevA=
$ base64 -d encrypted_blob > openssl_encrypted
$ head openssl_encrypted                               
$ openssl enc -d -blowfish -in openssl_encrypted -out openssl_decrypted -pass file:./for_later_wink_wink -md sha512 -pbkdf2 -iter 5
```

#### X509 Certificate

X.509 is a standard format for public key certificates, digital documents that securely associate cryptographic key pairs with identities such as websites, individuals, or organizations.

The flag is a x509 certificate attribute, specifically the Organization (O) attribute

```bash
$ openssl x509 -in openssl_decrypted -text > openssl_x509_info
$ head openssl_x509_info
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            19:4b:62:7a:08:9d:19:5f:bb:ff:68:bf:b8:0b:f8:a3:aa:5c:7c:0f
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = AU, ST = Victoria, L = Melbourne, O = flag_{b32a808aa0c2f6bd8fe0cf55cae64d8c}, OU = 546 Troop, CN = Jackery Fibson, emailAddress = jackery.fibson@403.mail.com
        Validity
            Not Before: Nov 14 23:55:22 2021 GMT
            Not After : Jan  8 23:55:22 2023 GMT
```
