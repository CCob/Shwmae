using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace Shwmae.BCrypt {
    public class Key {
        public static byte[] ParseKey(BinaryReader reader) {

            var magic = reader.ReadUInt32();

            if (magic != 0x4D42444B) { //KDBM BCrypt key
                throw new FormatException("Policy key unexpected format");
            }

            var version = reader.ReadUInt32();

            if (version != 1) {
                throw new FormatException("Policy key unexpected format version");
            }
            return reader.ReadBytes(reader.ReadInt32());
        }
    }
}
