using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dahomey.Cbor.Attributes;
using NtApiDotNet;
using DPAPI;
using Shwmae.Ngc.Keys.Crypto;

namespace Shwmae.Ngc.Keys {


    public class NgcKey
    {
        public string Name { get; private set; }
        public string KeyId { get; private set; }
        public string Provider { get; private set; }
        public string KeyPath { get; private set; }
        public string KeyType { get; private set; }
        public NgcContainer User { get; private set; }
        public X509Certificate2 Certificate { get; private set; }
        public bool IsSoftware { get; private set; }

        protected KeyCrypto crypto;


        public NgcKey(NgcContainer user, string path)
        {

            Name = NgcInterop.ReadNcgFileString(Path.Combine(path, "1.dat"));
            Provider = NgcInterop.ReadNcgFileString(Path.Combine(path, "2.dat"));
            KeyId = NgcInterop.ReadNcgFileString(Path.Combine(path, "3.dat"));
            KeyType = NgcInterop.ReadNcgFileString(Path.Combine(path, "12.dat"));
            User = user;

            if (File.Exists(Path.Combine(path, "4.dat")))
            {
                Certificate = new X509Certificate2(File.ReadAllBytes(Path.Combine(path, "4.dat")));
            }

            if (Provider == "Microsoft Platform Crypto Provider")
            {
                var keyName = SHA1.Create("SHA1").ComputeHash(Encoding.Unicode.GetBytes(KeyId)).Hex() + ".PCPKEY";
                var keys = Directory.EnumerateFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"ServiceProfiles\\LocalService\\AppData\\Local\Microsoft\Crypto\PCPKSP\\"), keyName, SearchOption.AllDirectories);

                if (keys.Count() > 0)
                {
                    KeyPath = keys.First();
                }

                crypto = new NgcPlatformKeyCrypto(KeyId);

            }
            else if (Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider)
            {

                var files = Directory.EnumerateFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"ServiceProfiles\\LocalService\\AppData\\Roaming\Microsoft\Crypto\Keys\"));

                KeyPath = Directory.EnumerateFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"ServiceProfiles\\LocalService\\AppData\\Roaming\Microsoft\Crypto\Keys\"))
                    .Where(kf => CNGKeyBlob.Parse(kf).Name.Equals(KeyId))
                    .FirstOrDefault();

                crypto = new NgcSoftwareKeyCrypto(KeyPath);
                IsSoftware = true;
            }
        }

        NgcKey(NgcContainer user, string provider, string id)
        {
            User = user;
            Provider = provider;
            Name = id;
        }

        public static IEnumerable<NgcKey> GetNgcKeys()
        {
            return new CngProvider("Microsoft Passport Key Storage Provider")
                .EnumerateKeys(CngKeyOpenOptions.None)
                .Select(k => new NgcKey(null, "Microsoft Passport Key Storage Provider", k.pszName));
        }

        static NgcKey CreateNgcKey(NgcContainer user, string path) {
            
            try { 
                var keyId = NgcInterop.ReadNcgFileString(Path.Combine(path, "1.dat"));

                if (keyId.StartsWith("login.windows.net/")) {
                    return new AzureADKey(user, path);
                } else if (File.Exists(Path.Combine(path, "7.dat"))) {
                    return new NgcPassKey(user, path);
                } else {
                    return new NgcKey(user, path);
                }
            }catch(CryptographicException ce) {
                return default;
            }
        }

        public byte[] Sign(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider, HashAlgorithmName alg)
        {
            return crypto.Sign(data, pin, masterKeyProvider, alg);
        }

        public byte[] Decrypt(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider)
        {
            return crypto.Decrypt(data, pin, masterKeyProvider);
        }

        public byte[] Dump(NgcPin pin, IMasterKeyProvider masterKeyProvider) {
            
            if (!IsSoftware) {
                throw new InvalidOperationException("Cannot dump TPM backed key");
            }

            return ((NgcSoftwareKeyCrypto)crypto).Export(pin, masterKeyProvider);
        }

        public static IEnumerable<NgcKey> GetNgcKeys(NgcContainer user)
        {

            List<NgcKey> result = new List<NgcKey>();

            foreach (var ngcUserDir in Directory.EnumerateDirectories(user.Path))
            {
                if (Guid.TryParse(Path.GetFileName(ngcUserDir), out Guid providerId))
                {
                    result.AddRange(Directory.EnumerateDirectories(ngcUserDir)
                        .Where(kd => File.Exists(Path.Combine(kd, "1.dat")))
                        .Select(kd => CreateNgcKey(user, kd)));
                }
            }

            return result;
        }

        public override string ToString()
        {
            return $"{Name} ({Provider})";
        }
    }
}
