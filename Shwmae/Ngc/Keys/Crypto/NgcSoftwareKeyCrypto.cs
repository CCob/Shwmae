using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using DPAPI;
using NLog.LayoutRenderers.Wrappers;

namespace Shwmae.Ngc.Keys.Crypto
{
    public class NgcSoftwareKeyCrypto : KeyCrypto
    {
        public int Rounds { get; private set; }
        public byte[] Salt { get; private set; }
        public CNGKeyBlob KeyBlob { get; private set; }
        public MasterKey MasterKey { get; private set; }

        public NgcSoftwareKeyCrypto(string path){
            KeyBlob = CNGKeyBlob.Parse(path);
        }

        public NgcSoftwareKeyCrypto(CNGKeyBlob keyBlob) {
            KeyBlob = keyBlob;
        }

        public void DecryptPrivateProperties(IMasterKeyProvider masterKeyProvider) {

            MasterKey = masterKeyProvider.GetMasterKey(KeyBlob.PrivateKey.GuidMasterKey);

            var privatePropertiesBlob = KeyBlob.PrivateProperties.Decrypt(MasterKey.Key, Encoding.UTF8.GetBytes("6jnkd5J3ZdQDtrsu\0"));

            if (privatePropertiesBlob.Length == 0) {
                throw new ArgumentException("keyBlob does not contain private key properties");
            }

            var privateProperties = CNGProperty.Parse(new BinaryReader(new MemoryStream(privatePropertiesBlob)), (uint)privatePropertiesBlob.Length);
            var uiPolicy = privateProperties.FirstOrDefault(p => p.Name == "UI Policy");

            if (uiPolicy.Equals(default)) {
                throw new ArgumentException("keyBlob does not contain UI policy");
            }

            var flags = BitConverter.ToInt32(uiPolicy.Value, 4);

            if ((flags & 0x3) >= 1) {

                var saltProp = privateProperties.FirstOrDefault(p => p.Name == "NgcSoftwareKeyPbkdf2Salt");
                var roundsProp = privateProperties.FirstOrDefault(p => p.Name == "NgcSoftwareKeyPbkdf2Round");

                Rounds = BitConverter.ToInt32(roundsProp.Value, 0);
                Salt = saltProp.Value;
            }
        }

        byte[] DecryptKey(NgcPin pin, IMasterKeyProvider masterKeyProvider) {

            DecryptPrivateProperties(masterKeyProvider);

            byte[] entropy;

            if (Salt == null) {
                entropy = pin.DeriveEntropy();
            } else {
                entropy = pin.DeriveEntropy(Salt, Rounds);
            }

            return KeyBlob.PrivateKey.Decrypt(MasterKey.Key, entropy);
        }

        CngKey LoadKey(NgcPin pin, IMasterKeyProvider masterKeyProvider){     
            return CngKey.Import(DecryptKey(pin, masterKeyProvider), CngKeyBlobFormat.GenericPrivateBlob, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        }

        public byte[] Sign(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider, HashAlgorithmName alg)
        {

            using (var cngKey = LoadKey(pin, masterKeyProvider))
            {

                if (cngKey.Algorithm == CngAlgorithm.Rsa)
                {
                    var rsa = new RSACng(cngKey);
                    return rsa.SignData(data, alg, RSASignaturePadding.Pkcs1);
                }
                else if (cngKey.Algorithm == CngAlgorithm.ECDsa)
                {
                    var ecdsa = new ECDsaCng(cngKey);
                    return ecdsa.SignData(data, alg);
                }
                else
                {
                    throw new NotImplementedException($"Algorithm {cngKey.Algorithm} not currently supported");
                }
            }
        }

        public byte[] Decrypt(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider)
        {

            using (var cngKey = LoadKey(pin, masterKeyProvider))
            {
                if (cngKey.Algorithm == CngAlgorithm.Rsa)
                {
                    var rsa = new RSACng(cngKey);
                    return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                }
                else if (cngKey.Algorithm == CngAlgorithm.ECDsa)
                {
                    throw new CryptographicException($"Key type {cngKey.Algorithm} doesn't support decryption");
                }
                else
                {
                    throw new NotImplementedException($"Algorithm {cngKey.Algorithm} not currently supported");
                }
            }
        }

        public byte[] Export(NgcPin pin, IMasterKeyProvider masterKeyProvider) {

            var cngKey = DecryptKey(pin, masterKeyProvider);

            var keyParams = new CngKeyCreationParameters {
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                KeyCreationOptions = CngKeyCreationOptions.None ,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            keyParams.Parameters.Add(new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, cngKey, CngPropertyOptions.None));
            var key = CngKey.Create(CngAlgorithm.Rsa, null, keyParams);
            return key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }
    }
}
