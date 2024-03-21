using System.IO;
using BCrypt;

namespace Shwmae.Ngc.Protectors {

    public enum BioEncryptionType {
        Aes = 1,
        Tpm = 2
    }
    public class BioProtector : NgcProtector
    {

        public byte[] AesAuthData { get; private set; }
        public byte[] AesTag { get; private set; }
        public byte[] AesNonce { get; private set; }
        public byte[] AesEncBioKeys { get; private set; }

        public BioEncryptionType BioEncryptionType { get; }

        public BioProtector(NgcContainer user, string path) : base(user, path)
        {

            var reader = new BinaryReader(new MemoryStream(EncryptedProtector));
            BioEncryptionType = (BioEncryptionType)reader.ReadUInt32();

            if (BioEncryptionType == BioEncryptionType.Aes)
            {

                var authDataLen = reader.ReadInt32();
                var nonceLen = reader.ReadInt32();
                var encBioKeyLen = reader.ReadInt32();
                var tagLen = reader.ReadInt32();

                AesNonce = reader.ReadBytes(nonceLen);
                AesEncBioKeys = reader.ReadBytes(encBioKeyLen);
                AesTag = reader.ReadBytes(tagLen);
                reader.BaseStream.Seek(0, SeekOrigin.Begin);
                AesAuthData = reader.ReadBytes(authDataLen);
            }
        }

        public override ProtectorType ProtectorType => ProtectorType.Bio;

        public override void Decrypt(byte[] secret)
        {
            if (BioEncryptionType == BioEncryptionType.Aes)
            {
                var reader = new BinaryReader(new MemoryStream(AESGCM.GcmDecrypt(AesEncBioKeys, secret, AesNonce, AesTag, AesAuthData)));
                reader.ReadBytes(0x48); //skip unknown header
                ParsePinKeys(reader);
            }
        }
    }
}
