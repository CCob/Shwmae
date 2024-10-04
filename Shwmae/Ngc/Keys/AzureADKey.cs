using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JWT.Builder;
using JWT;
using JWT.Algorithms;
using System.Linq;
using Shwmae.Ngc.Keys.Crypto;
using DPAPI;
using System.Text;
using Microsoft.Win32;
using Shwmae.Ngc.Protectors;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using OktaTerrify.Signers;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using BCrypt;
using Jose;


namespace Shwmae.Ngc.Keys {


    [StructLayout (LayoutKind.Sequential)]
    public struct BCRYPT_OAEP_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string AlgId;
        public IntPtr Label;
        public uint LabelSize;
    }  


    public class JwtSignerRS256 : IJwtAlgorithm {

        KeyCrypto keyCrypto;
        IMasterKeyProvider masterKeyProvider;

        public JwtSignerRS256(KeyCrypto keyCrypto, IMasterKeyProvider masterKeyProvider) {
            this.keyCrypto = keyCrypto;
            this.masterKeyProvider = masterKeyProvider;
        }

        public string Name => "RS256";

        public HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        public byte[] Sign(byte[] key, byte[] bytesToSign) {
            return keyCrypto.Sign(bytesToSign, new NgcPin(key), masterKeyProvider, HashAlgorithmName);
        }
    }
    
    public class AzureADKey : NgcKey {

        public string AzureKid { get; private set; }
        public string Email { get; private set; }
        public string TenantId { get; private set; }
        public string Idp {  get; private set; }
        public string PartialTGT { get; private set; }
        public string PRT { get; private set; }
        public string TransportKeyName { get; private set; }
        public byte[] EncryptedPopSessionKey { get; private set; }
        public byte[] DerivedSessionKey { get; private set; }
        public byte[] Ctx { get; private set;}
        public string PRTRefreshToken { get; private set; }

        public AzureADKey(NgcContainer user, string path) : base(user, path) {

            var match = Regex.Match(Name, "(.*)/(.*)/(.*)");

            if (match.Success) {
                Idp = match.Groups[1].Value;
                TenantId = match.Groups[2].Value;
                Email = match.Groups[3].Value;                
            }  
            
            var cngKey = CngKey.Open(KeyId, new CngProvider(Provider));
            AzureKid = Convert.ToBase64String(new SHA256Managed().ComputeHash(cngKey.Export(CngKeyBlobFormat.GenericPublicBlob)));                        
        }

        CngKey GetTransportKey() {

            var idpHash = new SHA256Managed().ComputeHash(Encoding.Unicode.GetBytes(Idp)).Hex();
            var tenantHash = new SHA256Managed().ComputeHash(Encoding.Unicode.GetBytes(TenantId)).Hex();
            var emailHash = new SHA256Managed().ComputeHash(Encoding.Unicode.GetBytes(Email)).Hex();
            var deviceTransportKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\{idpHash}\{tenantHash}", false);
            string keyName;
            
            if (Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider) {
                keyName = (string)deviceTransportKey.GetValue("SoftwareKeyTransportKeyName");                
            } else {
                keyName = (string)deviceTransportKey.GetValue("TpmKeyTransportKeyName");                
            }

            TransportKeyName = keyName;           

            return CngKey.Open(keyName, new CngProvider(Provider));
        }

        byte[] DecryptSessionKey(byte[] encryptedKey) {

            SECURITY_STATUS status;

            using (var transportKey = GetTransportKey()) {
                
                if ((status = NgcInterop.NCryptImportKey(transportKey.ProviderHandle, transportKey.Handle, "OpaqueTransport", IntPtr.Zero, out var derivationKey, encryptedKey, (uint)encryptedKey.Length, 0)) != SECURITY_STATUS.ERROR_SUCCESS) {
                    throw new CryptographicException($"Failed to import session key: 0x{status:x}");
                }
                
                if((status = NgcInterop.NCryptExportKey(derivationKey, IntPtr.Zero, "OpaqueTransport", IntPtr.Zero, null, 0, out var size, 0x800)) != SECURITY_STATUS.ERROR_SUCCESS) {
                    throw new CryptographicException($"Failed to get session key size: 0x{status:x}");
                }

                var sessionKeyBlob = new byte[size];

                if ((status = NgcInterop.NCryptExportKey(derivationKey, IntPtr.Zero, "OpaqueTransport", IntPtr.Zero, sessionKeyBlob, (uint)sessionKeyBlob.Length, out size, 0x800)) != SECURITY_STATUS.ERROR_SUCCESS) {
                    throw new CryptographicException($"Failed to get session key size: 0x{status:x}");
                }

                return sessionKeyBlob;
            }            
        }

        byte[] GetDerivedKeyFromSessionKey(byte[] ctx, byte[] jwt, byte[] encryptedKey) {
            var sha256 = SHA256.Create();
            var ctxv2 = sha256.ComputeHash(ctx.Concat(jwt).ToArray());
            return GetDerivedKeyFromSessionKey(ctxv2, encryptedKey);
        }

        byte[] GetDerivedKeyFromSessionKey(byte[] ctx, byte[] encryptedKey) {

            SECURITY_STATUS status;

            using (var transportKey = GetTransportKey()) {

                if ((status = NgcInterop.NCryptImportKey(transportKey.ProviderHandle, transportKey.Handle, "OpaqueTransport", IntPtr.Zero, out var derivationKey, encryptedKey, (uint)encryptedKey.Length, 0)) != SECURITY_STATUS.ERROR_SUCCESS) {
                    throw new CryptographicException($"Failed to import transport key: 0x{status:x}");
                }

                byte[] derivedKey = new byte[32];

                unsafe {

                    var buffers = new NCryptBuffer[] {
                        new NCryptBuffer (BufferType.KDF_LABEL, Encoding.UTF8.GetBytes("AzureAD-SecureConversation")),
                        new NCryptBuffer (BufferType.KDF_CONTEXT, ctx),
                        new NCryptBuffer (BufferType.KDF_HASH_ALGORITHM, Encoding.Unicode.GetBytes("SHA256\0"))                
                    };

                    fixed (NCryptBuffer* buffAddress = &buffers[0]) {
                        var desc = NCryptBufferDesc.Create();
                        desc.cBuffers = buffers.Length;
                        desc.pBuffers = buffAddress;
                        
                        if((status = NgcInterop.NCryptKeyDerivation(derivationKey, &desc, derivedKey, derivedKey.Length, out var written, 0)) != SECURITY_STATUS.ERROR_SUCCESS) {
                            throw new CryptographicException($"Failed to derive session key for ctx {ctx.Hex()}: 0x{status:x}");
                        }

                        return derivedKey;
                    }
                }
            }        
        }

        string GeneratatePRTRequestJWT(NgcProtector protector, RSACng deviceKey, X509Certificate2 deviceCert, IMasterKeyProvider masterKeyProvider,  string requestNonce) {

            var dateTimeProvider = new UtcDateTimeProvider();            
            var algorithm = new CngRSAAlgorithm(deviceKey);

            return JwtBuilder.Create()
                .AddHeader("kid", AzureKid)
                .AddHeader("typ", "JWT")
                .AddHeader("x5c", Convert.ToBase64String(deviceCert.Export(X509ContentType.Cert)))

                .AddClaim("request_nonce", requestNonce)
                .AddClaim("scope", "openid aza ugs")
                .AddClaim("win_ver", "10.0.22621.2792")
                .AddClaim("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .AddClaim("username", Email)
                .AddClaim("assertion", GenerateAssertionJWT(protector, requestNonce, masterKeyProvider))
                .AddClaim("group_sids", new string[] { })
                .AddClaim("client_id", "38aa3b87-a06d-4817-b275-7a316988d93b")

                .WithAlgorithm(algorithm)
                .WithDateTimeProvider(dateTimeProvider)
                .WithSecret(protector.SignPin)
                .Encode();
        }

        string GenerateAssertionJWT(NgcProtector protector, string requestNonce, IMasterKeyProvider masterKeyProvider) {
    
            var dateTimeProvider = new UtcDateTimeProvider();
            var issueTime = DateTime.UtcNow;
            var algorithm = new JwtSignerRS256(crypto, masterKeyProvider);

            return JwtBuilder.Create()
                .AddHeader("kid", AzureKid)  
                .AddHeader("typ", "JWT")
                .AddHeader("use", "ngc")

                .Audience(TenantId.ToUpper())
                .Issuer(Email)
                .IssuedAt(issueTime)
                .ExpirationTime(issueTime.AddMinutes(5))
                .AddClaim("request_nonce", requestNonce)
                .AddClaim("scope", "openid aza ugs")

                .WithAlgorithm(algorithm)
                .WithDateTimeProvider(dateTimeProvider)
                .WithSecret(protector.SignPin)
                .Encode();
        }

        
        public static X509Certificate2 FindDeviceCert() {

            using (var joinInfo = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo")) {
                if (joinInfo != null) {
                    var certThumprint = joinInfo.GetSubKeyNames().FirstOrDefault();
                    X509Store store = new X509Store(StoreLocation.LocalMachine);
                    store.Open(OpenFlags.MaxAllowed);

                    foreach (var cert in store.Certificates) {
                        if (cert.Thumbprint.Equals(certThumprint, StringComparison.OrdinalIgnoreCase)) {
                            return cert;
                        }
                    }
                }

                return null;            
            }
        }

        public string GeneratePRTRenewalJWT(string nonce, string prtRefreshToken, bool kdfv1, byte[] secret) {

            var builder = JwtBuilder.Create()
 
                .AddHeader("ctx", Convert.ToBase64String(Ctx))
                .AddHeader("kdf_ver", kdfv1 ? 1 : 2)

                .AddClaim("request_nonce", nonce)
                .AddClaim("scope", "openid aza ugs")
                .AddClaim("win_ver", "10.0.22621.2792")
                .AddClaim("grant_type", "refresh_token")
                .AddClaim("iss", "aad:brokerplugin")
                .AddClaim("group_sids", new string[] { })
                .AddClaim("client_id", "38aa3b87-a06d-4817-b275-7a316988d93b")
                .AddClaim("refresh_token", prtRefreshToken)
                .AddClaim("previous_refresh_token", prtRefreshToken);
                      
            if(secret == null) {
                return builder.WithAlgorithm(new NoneAlgorithm())
                        .Encode();
            } else {
                return builder.WithAlgorithm(new HMACSHA256Algorithm())
                        .WithSecret(secret)
                        .Encode();
            }           
        }

        public void RenewPRT(string sessionKey, string refreshToken, bool kdfv1) {

            Ctx = new byte[24];
            PRTRefreshToken = refreshToken;
            EncryptedPopSessionKey = Utils.Base64Url(sessionKey);

            var tokenURL = $"https://login.microsoftonline.com/{TenantId}/oauth2/token";
            var httpClient = new HttpClient();
            var response = httpClient.PostAsync(tokenURL,
                new FormUrlEncodedContent(new KeyValuePair<string, string>[] { new KeyValuePair<string, string>("grant_type", "srv_challenge") }))
                .Result.Content.ReadAsStringAsync().Result;

            var obj = JsonConvert.DeserializeObject<dynamic>(response);
            JwtBuilder prtRenewJWT = null;
            new Random().NextBytes(Ctx);
            var dateTimeProvider = new UtcDateTimeProvider();

            using (var impersonteCtx = Utils.Impersonate("SYSTEM")) {
                if (!kdfv1) {
                    var tmpJWT = GeneratePRTRenewalJWT((string)obj.Nonce, PRTRefreshToken, kdfv1, null);
                    DerivedSessionKey = GetDerivedKeyFromSessionKey(Ctx, Utils.Base64Url(tmpJWT.Split('.')[1]), EncryptedPopSessionKey);
                } else {
                    DerivedSessionKey = GetDerivedKeyFromSessionKey(Ctx, EncryptedPopSessionKey);
                }
            }
                                   
            var jwtToken = GeneratePRTRenewalJWT((string)obj.Nonce, PRTRefreshToken, kdfv1, DerivedSessionKey);

            response = httpClient.PostAsync(tokenURL,
                    new FormUrlEncodedContent(new KeyValuePair<string, string>[] {
                    new KeyValuePair<string, string>("request", jwtToken),
                    new KeyValuePair<string, string>("windows_api_version", "2.2"),
                    new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_info", "1"),
                    new KeyValuePair<string, string>("tgt", "true"),
                }))
                .Result.Content.ReadAsStringAsync().Result;

            var key = Jose.JWT.Headers(response);
            var token = Jose.JweToken.FromString(response);

            using (var impersonteCtx = Utils.Impersonate("SYSTEM")) {
                DerivedSessionKey = GetDerivedKeyFromSessionKey(Convert.FromBase64String((string)key["ctx"]), EncryptedPopSessionKey);
            }

            byte[] decryptedData;

            if (token.Iv.Length == 12) {
                decryptedData = AESGCM.GcmDecrypt(token.Ciphertext, DerivedSessionKey, token.Iv, token.AuthTag);
            } else {
                decryptedData = Utils.AesDecrypt(token.Ciphertext, DerivedSessionKey, token.Iv);
            }

            ParsePRT(Encoding.UTF8.GetString(decryptedData), true);
        }

        public void GetPRT(NgcProtector ngcKeySet, IMasterKeyProvider masterKeyProvider, RSACng deviceKey, X509Certificate2 deviceCert, bool useKDFv1) {

            var tokenURL = $"https://login.microsoftonline.com/{TenantId}/oauth2/token";
            var httpClient = new HttpClient();
            var response = httpClient.PostAsync(tokenURL,
                new FormUrlEncodedContent(new KeyValuePair<string, string>[] { new KeyValuePair<string, string>("grant_type", "srv_challenge") }))
                .Result.Content.ReadAsStringAsync().Result;

            var obj = JsonConvert.DeserializeObject<dynamic>(response);
            dynamic prt;

            using (var ctx = Utils.Impersonate("Ngc")) {

                var prtRequestJwt = GeneratatePRTRequestJWT(ngcKeySet, deviceKey, deviceCert, masterKeyProvider, (string)obj.Nonce);
                
                response = httpClient.PostAsync(tokenURL,
                    new FormUrlEncodedContent(new KeyValuePair<string, string>[] {
                    new KeyValuePair<string, string>("request", prtRequestJwt),
                    new KeyValuePair<string, string>("windows_api_version", "2.2"),
                    new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new KeyValuePair<string, string>("tgt", "true"),
                    }))
                    .Result.Content.ReadAsStringAsync().Result;                             
            }

            ParsePRT(response, false);           
            return;
        }

        void ParsePRT(string response, bool renewal) {

            PRT = response;
            var prt = JsonConvert.DeserializeObject<dynamic>(response);
            PRTRefreshToken = prt["refresh_token"];
            var sessionKey = (string)prt.session_key_jwe;

            if (!renewal) {
                EncryptedPopSessionKey = Utils.Base64Url(sessionKey.Split(new char[] { '.' })[1]);
            }
            
            var tgt_ad = JsonConvert.DeserializeObject<dynamic>((string)prt.tgt_ad);

            if (tgt_ad != null && tgt_ad.clientKey != null) {

                using (var impersonteCtx = Utils.Impersonate("SYSTEM")) {

                    Ctx = new byte[24];
                    new Random().NextBytes(Ctx);
                    DerivedSessionKey = GetDerivedKeyFromSessionKey(Ctx, EncryptedPopSessionKey);
                    byte[] tgtSessionKey;

                    if (!renewal) {
                        var tgt_key = Jose.JWT.Headers((string)tgt_ad.clientKey);
                        var tgt_token = Jose.JweToken.FromString((string)tgt_ad.clientKey);
                        var tgtpopSessionKey = GetDerivedKeyFromSessionKey(Convert.FromBase64String((string)tgt_key["ctx"]), EncryptedPopSessionKey);
                        var decryptedTPMSessionKey = DecryptSessionKey(EncryptedPopSessionKey);
                        tgtSessionKey = Utils.AesDecrypt(tgt_token.Ciphertext, tgtpopSessionKey, tgt_token.Iv);
                    } else {
                        tgtSessionKey = Convert.FromBase64String((string)tgt_ad.clientKey);
                    }

                    var tgtCrypto = CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96);
                    var asRep = KrbAsRep.DecodeApplication(Convert.FromBase64String((string)tgt_ad.messageBuffer));
                    var krbCred = tgtCrypto.Decrypt(asRep.EncPart.Cipher, new KerberosKey(tgtSessionKey), KeyUsage.EncAsRepPart);
                    var krbCredObj = KrbEncAsRepPart.DecodeApplication(krbCred);

                    var krbCredInfo = new KrbCredInfo();
                    krbCredInfo.Key = new KrbEncryptionKey() { EType = EncryptionType.AES256_CTS_HMAC_SHA1_96, KeyValue = krbCredObj.Key.KeyValue, Usage = KeyUsage.EncAsRepPart };
                    krbCredInfo.Realm = krbCredObj.Realm;
                    krbCredInfo.AuthTime = krbCredObj.AuthTime;
                    krbCredInfo.StartTime = krbCredObj.StartTime;
                    krbCredInfo.EndTime = krbCredObj.EndTime;
                    krbCredInfo.SName = krbCredObj.SName;
                    krbCredInfo.RenewTill = krbCredObj.RenewTill;
                    krbCredInfo.PName = asRep.CName;
                    krbCredInfo.Flags = krbCredObj.Flags;
                    krbCredInfo.SRealm = krbCredObj.Realm;

                    PartialTGT = Convert.ToBase64String(KrbCred.WrapTicket(asRep.Ticket, krbCredInfo).EncodeApplication().ToArray());
                }
            }
            else
            {
                // We still want to have a Ctx + derived key combination as long as KDFv1 works
                using (var impersonteCtx = Utils.Impersonate("SYSTEM"))
                {
                    Ctx = new byte[24];
                    new Random().NextBytes(Ctx);
                    DerivedSessionKey = GetDerivedKeyFromSessionKey(Ctx, EncryptedPopSessionKey);
                }
            }
        }
    }
}
