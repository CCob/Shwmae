
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Shwmae.Fido2 {
    class AuthenticatorData {

        public byte[] RpIdHash;
        public byte Flags;
        public uint SignCount;

        public AuthenticatorData(string rpId, uint signCount) {

            RpIdHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rpId));
            Flags = 5;  //user presence + user verification
            SignCount = signCount;
        }
        public byte[] ToByteArray() {
            using (var bw = new BinaryWriter(new MemoryStream())) {
                bw.Write(RpIdHash);
                bw.Write(Flags);
                bw.Write(IPAddress.HostToNetworkOrder((int)SignCount));
                bw.Flush();
                return ((MemoryStream)bw.BaseStream).ToArray();                    
            }
        }
    }
}