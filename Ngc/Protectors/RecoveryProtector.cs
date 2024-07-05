using System;
using System.IO;
using System.Security.Cryptography;

namespace Shwmae.Ngc.Protectors {
    public class RecoveryProtector : NgcProtector
    {
        //makes call to POST cred.microsoft.com/unprotectsecret/v1
        //response is sent to CryptUnprotectData with local machine DPAPI key
        //decrypted DPAPI blob is used as AES key for EncryptedProtector 

        public override ProtectorType ProtectorType => ProtectorType.Recovery;

        public byte[] IV { get; private set; }
        public byte[] Data9 { get; private set; }
        
        public RecoveryProtector(NgcContainer user, string path) : base(user, path)
        {
            IV = File.ReadAllBytes(Path.GetFullPath(Path.Combine(path, @"4.dat")));
            Data9 = File.ReadAllBytes(Path.GetFullPath(Path.Combine(path, @"9.dat")));         
        }

        public override void Decrypt(byte[] secret)
        {
            var reader = new BinaryReader(new MemoryStream(Utils.AesDecrypt(EncryptedProtector, secret, IV)));  
            ParsePinKeys(reader);           
        }
    }
}
