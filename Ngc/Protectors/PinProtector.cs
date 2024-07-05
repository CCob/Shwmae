using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Dahomey.Cbor.Serialization;
using DPAPI;
using Kerberos.NET.Crypto;
using Shwmae.Ngc.Keys.Crypto;

namespace Shwmae.Ngc.Protectors {

    public enum PinType {
        Numeric,
        Passcode
    }

    public class PinProtector : NgcProtector
    {

        public PinType PinType { get; private set; }
        public int PinLength { get; private set; }
        public string Provider { get; private set; }
        public string DecryptKeyId { get; private set; }
        public override ProtectorType ProtectorType => ProtectorType.Pin;
        public string Hash { get; private set; }
        public bool IsSoftware { get; private set; } 

        NgcSoftwareKeyCrypto softwareKey;
        IMasterKeyProvider masterKeyProvider;

        public PinProtector(NgcContainer user, string path) : base(user, path)
        {
            Provider = NgcInterop.ReadNcgFileString(Path.GetFullPath(Path.Combine(path, @"1.dat")));
            var pinDetails = File.ReadAllBytes(Path.GetFullPath(Path.Combine(path, @"7.dat")));
            PinLength = BitConverter.ToUInt16(pinDetails, 2);

            if (PinLength > 0)
            {
                PinType = PinType.Numeric;
            }
            else
            {
                PinType = PinType.Passcode;
            }

            if (Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider)
            {
                DecryptKeyId = NgcInterop.ReadNcgFileString(Path.GetFullPath(Path.Combine(path, @"2.dat")));
                softwareKey = new NgcSoftwareKeyCrypto(CNGKeyBlob.Find(DecryptKeyId));
                IsSoftware = true;
            }
        } 
        
        public byte[] DecryptSoftwareKey(byte[] secret) {    
            
            if(masterKeyProvider == null) {
                throw new InvalidOperationException("ProcessSoftwareKey function not called");
            }

            var pin = new NgcPin(Encoding.Unicode.GetString(secret));
            return softwareKey.Decrypt(EncryptedProtector, pin, masterKeyProvider);                    
        }

        public byte[] DecryptHardwareKey(byte[] secret) {
            return NgcSeal.Unseal(EncryptedProtector, new NgcPin(Encoding.Unicode.GetString(secret)));
        }

        public override void Decrypt(byte[] secret){
            Func<byte[], byte[]> decryptFunc = IsSoftware ? DecryptSoftwareKey : DecryptHardwareKey;
            var br = new BinaryReader(new MemoryStream(decryptFunc(secret)));
            ParsePinKeys(br);
        }

        public void ProcessSoftwareKey(IMasterKeyProvider masterKeyProvider) {
            
            if(!IsSoftware) {
                throw new InvalidOperationException("Windows Hello PIN hash cracking only works with software backed key");
            }

            softwareKey.DecryptPrivateProperties(masterKeyProvider);
            this.masterKeyProvider = masterKeyProvider;
            byte[] entropy = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA\0");
            Hash = $"$WINHELLO$*{(AlgId)softwareKey.KeyBlob.PrivateKey.HashAlgo}*{softwareKey.Rounds}*{softwareKey.Salt.Hex()}*{softwareKey.KeyBlob.PrivateKey.Signature.Hex()}*{softwareKey.MasterKey.Key.Hex()}*{softwareKey.KeyBlob.PrivateKey.HMAC.Hex()}*{softwareKey.KeyBlob.PrivateKey.Blob.Hex()}*{entropy.Hex()}";                        
        }
    }
}
