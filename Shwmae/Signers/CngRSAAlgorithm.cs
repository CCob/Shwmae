using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using JWT.Algorithms;
using Shwmae.Ngc;

namespace OktaTerrify.Signers {
    public class CngRSAAlgorithm : IAsymmetricAlgorithm {

      
        public string Name => "RS256";
        bool keyIsFile = false;
        string contextTitle = "Okta Terrify Pwner";
        RSACng rsaKey;

        public HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        public CngRSAAlgorithm(bool keyIsFile, string contextTitle) {
            this.keyIsFile = keyIsFile;
            this.contextTitle = contextTitle;
        }

        public CngRSAAlgorithm(bool keyIsFile) : this(keyIsFile, "Okta Terrify Pwner") {
            this.keyIsFile = keyIsFile;
        }

        public CngRSAAlgorithm(RSACng key) {
            this.rsaKey = key;       
        }

        public byte[] Sign(byte[] key, byte[] bytesToSign) {

            CngKey cngKey;
            var keyName = Encoding.ASCII.GetString(key);
            bool isBio = false;
            string providerName;
            CngProvider provider;

            if (key == null) {

                if (!keyIsFile) {

                    var match = Regex.Match(keyName, "(.*)//(.*)//(.*)");
                    var keyId = match.Groups[3].Value;
                    var party = match.Groups[2].Value;

                    if (keyId.StartsWith("HDW")) {
                        providerName = "Microsoft Platform Crypto Provider";
                    } else if (keyId.StartsWith("SFT"))
                        providerName = "Microsoft Software Key Storage Provider";
                    else {
                        providerName = "Microsoft Passport Key Storage Provider";
                        isBio = true;
                    }

                    provider = new CngProvider(providerName);

                    if (CngKey.Exists(keyName, provider))
                        cngKey = CngKey.Open(keyName, provider, CngKeyOpenOptions.Silent);
                    else
                        throw new CryptographicException($"Key {keyName} not found");

                } else {

                    if (!File.Exists(keyName)) {
                        throw new ArgumentException($"Key file with ID {keyName} cannot be found");
                    }

                    cngKey = CngKey.Import(File.ReadAllBytes(keyName), CngKeyBlobFormat.GenericPrivateBlob);
                    keyName = Path.GetFileName(keyName);
                    providerName = "Local Disk";
                }

                using (cngKey) {

                    if (isBio) {
                        cngKey.SetProperty(new CngProperty("Use Context", Encoding.Unicode.GetBytes($"{contextTitle}\0"), CngPropertyOptions.None));
                        cngKey.ParentWindowHandle = Process.GetCurrentProcess().MainWindowHandle;
                    }

                    Console.WriteLine($"[=] Opened key {keyName} from provider {providerName} under account {WindowsIdentity.GetCurrent().Name} with type {cngKey.Algorithm.Algorithm} ({cngKey.AlgorithmGroup.AlgorithmGroup})");

                    if (cngKey.Algorithm == CngAlgorithm.Rsa) {
                        var rsa = new RSACng(cngKey);
                        return rsa.SignData(bytesToSign, HashAlgorithmName, RSASignaturePadding.Pkcs1);
                    } else if (cngKey.Algorithm == CngAlgorithm.ECDsa) {
                        var signKey = new ECDsaCng(cngKey);
                        return signKey.SignData(bytesToSign, HashAlgorithmName.SHA256);
                    } else {
                        throw new NotImplementedException($"Signing with key type {cngKey.Algorithm.Algorithm} not currently supported");
                    }
                }

            } else {
                return rsaKey.SignData(bytesToSign, HashAlgorithmName, RSASignaturePadding.Pkcs1);
            }
        }

        public bool Verify(byte[] bytesToSign, byte[] signature) {
            throw new NotImplementedException();
        }
    }
}
