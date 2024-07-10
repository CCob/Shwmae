using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Shwmae.Ngc.Protectors {

    public enum ProtectorType
    {
        Unknown,
        Pin = 1,
        Bio = 2,
        Recovery = 3,
        PreBoot = 5,
        CompanionDevice = 6
    }

    public abstract class NgcProtector
    {

        public NgcContainer User { get; protected set; }
        public byte[] EncryptedProtector { get; protected set; }
        public byte[] ExternalPin { get; protected set; }
        public byte[] DecryptPin { get; protected set; }
        public byte[] SignPin { get; protected set; }
        public abstract ProtectorType ProtectorType { get; }


        public NgcProtector(NgcContainer user, string path)
        {
            User = user;
            EncryptedProtector = File.ReadAllBytes(Path.Combine(path, @"15.dat"));
        }

        public static NgcProtector GetProtector(NgcContainer user, string path)
        {

            var protectorType = (ProtectorType)int.Parse(Path.GetFileName(path));

            switch (protectorType)
            {

                case ProtectorType.Pin:
                    return new PinProtector(user, path);
                case ProtectorType.Bio:
                    return new BioProtector(user, path);
                case ProtectorType.Recovery:
                    return new RecoveryProtector(user, path);
                default:
                    throw new NotSupportedException($"Protector type {protectorType} not currently supported");
            }
        }

        public static IEnumerable<NgcProtector> GetUserProtectors(NgcContainer user)
        {
            return Directory.EnumerateDirectories(Path.Combine(user.Path, "Protectors"))
                  .Select(p => GetProtector(user, p));
        }

        protected void ParsePinKeys(BinaryReader br) {

            var unkPinLen = br.ReadUInt32();
            var decPinLen = br.ReadUInt32();
            var signPinLen = br.ReadUInt32();

            ExternalPin = br.ReadBytes((int)unkPinLen);
            DecryptPin = br.ReadBytes((int)decPinLen);
            SignPin = br.ReadBytes((int)signPinLen);
        }

        public abstract void Decrypt(byte[] secret);
    }
}
