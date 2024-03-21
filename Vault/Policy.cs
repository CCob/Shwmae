using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DPAPI;

namespace Shwmae.Vault {
    public  class Policy {

        public uint Version { get; private set; }
        public Guid VaultId { get; private set; }
        public string Name { get; private set; }
        public DPAPI_BLOB PolicyKey { get; private set; }
        public byte[] Aes128Key { get; private set; }
        public byte[] Aes256Key {  get; private set; }

        public Policy(string file) {

            var reader = new BinaryReader(new FileStream(file, FileMode.Open, FileAccess.Read));

            Version = reader.ReadUInt32();

            if(Version == 1) {
                VaultId = new Guid(reader.ReadBytes(16));
                Name = Encoding.Unicode.GetString(reader.ReadBytes(reader.ReadInt32()));

                //skip unknown values
                reader.ReadBytes(12);
                var typeSize = reader.ReadUInt16();

                while (typeSize > 0) {
                    var type = reader.ReadUInt16();

                    if (type == 0) { //key
                        //skip unknown Guids
                        reader.ReadBytes(32);
                        var blobSize = reader.ReadUInt32();
                        PolicyKey = DPAPI_BLOB.Parse(reader);
                    }

                    typeSize = reader.ReadUInt16();
                };              
            }
        }

     
        public void Decrypt(MasterKey masterKey) {

            var data = PolicyKey.Decrypt(masterKey.Key);
            var reader = new BinaryReader(new MemoryStream(data));

            while (reader.BaseStream.Position < reader.BaseStream.Length) {
                var size = reader.ReadUInt32();                               
                var version = reader.ReadUInt32();
                var keyType = reader.ReadUInt32();

                if (keyType == 1) {
                    Aes256Key = BCrypt.Key.ParseKey(reader);
                } else if (keyType == 2) {
                    Aes128Key = BCrypt.Key.ParseKey(reader);
                }                                
            }
        }
    }
}
