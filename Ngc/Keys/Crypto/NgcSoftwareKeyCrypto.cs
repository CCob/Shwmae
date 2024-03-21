using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using DPAPI;

namespace Shwmae.Ngc.Keys.Crypto
{
    public class NgcSoftwareKeyCrypto : KeyCrypto
    {

        CNGKeyBlob keyBlob;

        public NgcSoftwareKeyCrypto(string path)
        {
            keyBlob = CNGKeyBlob.Parse(path);
        }

        CngKey DecryptKey(NgcPin pin, IMasterKeyProvider masterKeyProvider)
        {

            var mk = masterKeyProvider.GetMasterKey(keyBlob.PrivateKey.GuidMasterKey);

            var privatePropertiesBlob = keyBlob.PrivateProperties.Decrypt(mk.Key, Encoding.UTF8.GetBytes("6jnkd5J3ZdQDtrsu\0"));

            byte[] entropy = null;

            if (privatePropertiesBlob.Length == 0)
            {
                throw new ArgumentException("keyBlob does not contain private key properties");
            }

            var privateProperties = CNGProperty.Parse(new BinaryReader(new MemoryStream(privatePropertiesBlob)), (uint)privatePropertiesBlob.Length);
            var uiPolicy = privateProperties.FirstOrDefault(p => p.Name == "UI Policy");

            if (uiPolicy.Equals(default))
            {
                throw new ArgumentException("keyBlob does not contain UI policy");
            }

            var flags = BitConverter.ToInt32(uiPolicy.Value, 4);

            if ((flags & 0x3) >= 1)
            {

                var saltProp = privateProperties.FirstOrDefault(p => p.Name == "NgcSoftwareKeyPbkdf2Salt");
                var roundsProp = privateProperties.FirstOrDefault(p => p.Name == "NgcSoftwareKeyPbkdf2Round");

                if (default(CNGProperty).Equals(saltProp) || default(CNGProperty).Equals(roundsProp))
                {
                    entropy = pin.DeriveEntropy();
                }
                else
                {
                    var rounds = BitConverter.ToInt32(roundsProp.Value, 0);
                    entropy = pin.DeriveEntropy(saltProp.Value, rounds);
                }
            };

            return CngKey.Import(keyBlob.PrivateKey.Decrypt(mk.Key, entropy), CngKeyBlobFormat.GenericPrivateBlob);
        }

        public byte[] Sign(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider, HashAlgorithmName alg)
        {

            using (var cngKey = DecryptKey(pin, masterKeyProvider))
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

            using (var cngKey = DecryptKey(pin, masterKeyProvider))
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
    }
}
