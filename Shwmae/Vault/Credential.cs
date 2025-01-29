using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NtApiDotNet;
using DPAPI;

namespace Shwmae.Vault {


    public class BioCredential : DecryptedCredential {

        public static readonly Guid SchemaId = Guid.Parse("f62c1ede-aa25-4575-ba52-c81ccfdd6dc6");

        public byte[] ProtectorKey { get; private set; } 

        public BioCredential(byte[] data) : base(data) {            
            var reader = new BinaryReader(new MemoryStream(Encoding.Unicode.GetString(Authenticator, 0, Authenticator.Length).FromHex()));
            var magic = reader.ReadUInt32();
            var version = reader.ReadUInt32();
            var keySize = reader.ReadInt32();
            ProtectorKey = reader.ReadBytes(keySize);           
        }
    }

    public class NgcCredential : DecryptedCredential {

        public static readonly Guid SchemaId = Guid.Parse("1d4350a3-330d-4af9-b3ff-a927a45998ac");

        public byte[] EncData { get; private set; }
        public byte[] IV {  get; private set; }
        public byte[] EncPassword { get; private set; }

        public NgcCredential(byte[] data) : base(data) {

            var reader = new BinaryReader(new MemoryStream(Authenticator));
            var version = reader.ReadUInt32();

            if(version != 1) {
                throw new FormatException($"Don't know how to parse version {version} NGC vault credential");
            }
            var encDataLen = reader.ReadInt32();
            var ivLen = reader.ReadInt32();
            var encPassLen = reader.ReadInt32();
            reader.ReadBytes(4); // skip unknown

            EncData = reader.ReadBytes(encDataLen);
            IV = reader.ReadBytes(ivLen);
            EncPassword = reader.ReadBytes(encPassLen);            
        }
    }

    public class DecryptedCredential {

        public uint Version { get; private set; }
        public uint Count { get; private set; }
        public Sid Identity { get; private set; }
        public string Resource { get; private set; }
        public byte[] Authenticator { get; private set; }

        public DecryptedCredential(byte[] data) {

            var reader = new BinaryReader(new MemoryStream(data));

            Version = reader.ReadUInt32();
            Count = reader.ReadUInt32();
            reader.ReadBytes(4); //skip unknown

            while(reader.BaseStream.Position < reader.BaseStream.Length) {
                var attribId = reader.ReadUInt32();
                var attribLength = reader.ReadInt32();
                var attribData = reader.ReadBytes(attribLength);

                if (attribId == 1) {
                    Resource = Encoding.Unicode.GetString(attribData, 0, attribData.Length-2);
                }else if(attribId == 2) {
                    Identity = new Sid(attribData);
                }else if(attribId == 3) {
                    Authenticator = attribData; //Encoding.Unicode.GetString(attribData, 0, attribData.Length); 
                }                
            }
        }
    }

    public class Credential {

        public Guid SchemaId { get; private set; }
        public DateTime LastWritten { get; private set; }
        public string Name { get; private set; }

        public byte[] IV { get; private set; }
        public byte[] Data {  get; private set; }

        public Credential(string path) { 

            var reader = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read));

            SchemaId = new Guid(reader.ReadBytes(16));            
            reader.ReadBytes(4); //skip unknown
            LastWritten = DateTime.FromFileTimeUtc(reader.ReadInt64());            
            reader.ReadBytes(8); //skip unknown 
            var nameData = reader.ReadBytes(reader.ReadInt32());
            Name = Encoding.Unicode.GetString(nameData,0,nameData.Length-2);

            var attributeMapSize = reader.ReadInt32();
            var attribCount = attributeMapSize / 12;
            var attribMap = new Dictionary<uint, uint>();

            while(attribCount-- > 0) {
                attribMap[reader.ReadUInt32()] = reader.ReadUInt32();
                reader.ReadBytes(4); //skip unknown                
            }

            var lastAttrib = attribMap.Max(a => a.Value);

            //skip all dynamic attributes
            reader.BaseStream.Seek(lastAttrib + 16, SeekOrigin.Begin);

            var attrib0 = reader.ReadUInt32();
            reader.ReadBytes(2); //skip unknown

            if(attrib0 != 0) {
                throw new FormatException("Unexpected vcrd layout");
            }

            var attribSize = reader.ReadInt32();
            var version = reader.ReadByte();

            if(version != 1) {
                throw new FormatException($"Unexpected version {version} for encrypted data attribute");
            }

            IV = reader.ReadBytes(reader.ReadInt32());
            Data = reader.ReadBytes(attribSize - IV.Length - 5);            
        }

        public DecryptedCredential Decrypt(Policy policy) {

            using (var aes = new AesManaged()) {
                aes.IV = IV;
                aes.Key = policy.Aes256Key;

                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) {
                        cs.Write(Data, 0, Data.Length);
                        cs.FlushFinalBlock();

                        if(SchemaId == BioCredential.SchemaId )
                            return new BioCredential(ms.ToArray());
                        else if(SchemaId == NgcCredential.SchemaId) {
                            return new NgcCredential(ms.ToArray());
                        } else {
                            return new DecryptedCredential(ms.ToArray());
                        }
                    }                    
                }
            }
        }

        public static IEnumerable<Credential> GetCredentials(string path) {
            var files = Directory.GetFiles(path, "*.vcrd");
            var creds = new List<Credential>();
            foreach (var file in files) {
                try  {
                    var c = new Credential(file);
                    creds.Add(c);
                } 
                catch { }
            }
            return creds;            
        }
    }
}
