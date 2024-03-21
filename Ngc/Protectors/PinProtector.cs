using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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
            }
        }

        public override void Decrypt(byte[] secret)
        {
            var br = new BinaryReader(new MemoryStream(NgcSeal.Unseal(EncryptedProtector, new NgcPin(Encoding.Unicode.GetString(secret)))));
            ParsePinKeys(br);
        }
    }
}
