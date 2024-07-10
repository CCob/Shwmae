using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Asn1;
using Dahomey.Cbor;
using Dahomey.Cbor.ObjectModel;
using DPAPI;
using Newtonsoft.Json.Converters;
using Shwmae.BCrypt;
using Shwmae.Fido2;
using Shwmae.Ngc.Protectors;

namespace Shwmae.Ngc.Keys
{
    public class NgcPassKey : NgcKey
    {
        public string RpId { get; private set; }
        public string UserName { get; private set; }
        public string DisplayName { get; private set; }
        public byte[] UserId { get; private set; }
        public byte[] PublicKey { get; private set; }
        public byte[] CredentialId { get; private set; }
        public byte[] Icon { get; private set; }
        public uint SignCount { get; private set; }

        string signCountPath;

        public NgcPassKey(NgcContainer user, string path) : base(user, path)
        {
            signCountPath = Path.Combine(path, "11.dat");
            SignCount = BitConverter.ToUInt32(File.ReadAllBytes(signCountPath),0);
            var passkeyInfo = File.ReadAllBytes(Path.Combine(path, "7.dat"));
            var passkeyObj = Cbor.Deserialize<CborObject>(passkeyInfo);

            if (passkeyObj.TryGetValue(CborValueConvert.ToValue(2), out var rpInfo)){
                RpId = StripQuotes(((CborObject)rpInfo)[CborValueConvert.ToValue("id")].ToString());
            }

            if (passkeyObj.TryGetValue(CborValueConvert.ToValue(3), out var userInfo))
            {
                var userId = ((CborObject)userInfo)[CborValueConvert.ToValue("id")].ToString();

                if (userId[0] == 'h') {
                    UserId = userId.Substring(2, userId.Length - 2).FromHex();
                } else {
                    throw new NotImplementedException("Only hex encoded string type currently supported");
                }            

                UserName = StripQuotes(((CborObject)userInfo)[CborValueConvert.ToValue("name")].ToString());
                DisplayName = StripQuotes(((CborObject)userInfo)[CborValueConvert.ToValue("displayName")].ToString());
            }

            using (var key = CngKey.Open(KeyId, new CngProvider(Provider))) {

                byte[] rawKey = null;

                if (key.AlgorithmGroup == CngAlgorithmGroup.Rsa) {
                    PublicKey = key.Export(CngKeyBlobFormat.GenericPublicBlob);
                    //skip BCRYPT_RSAKEY_BLOB header size
                    rawKey = PublicKey.Skip(0x18).ToArray();
                } else if (key.AlgorithmGroup == CngAlgorithmGroup.ECDsa) {
                    //skip BCRYPT_ECCKEY_BLOB header size
                    PublicKey = key.Export(CngKeyBlobFormat.EccPublicBlob);
                    rawKey = PublicKey.Skip(8).ToArray();
                }                
               
                CredentialId = SHA256.Create().ComputeHash(rawKey);                
            }
        }
        byte[] RawSignatureToECDA(byte[] data) {

            var r = data.Take(data.Length / 2).ToArray();
            var s = data.Skip(data.Length / 2).ToArray();

            return AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                AsnElt.MakeInteger(r),
                AsnElt.MakeInteger(s)
            }).Encode();
        }

        byte[] ToClientDataJSON(string origin, byte[] challenge) {
            return Encoding.UTF8.GetBytes($@"{{""type"":""webauthn.get"",""challenge"":""{Utils.Base64Url(challenge)}"",""origin"":""{origin}"",""isCrossOrigin"":""false"",""other_keys_can_be_added_here"":""do not compare clientDataJSON against a template. See https://goo.gl/yabPex""}}");
        }

        public PublicKeyCredential SignAssertion(byte[] challenge, string origin, NgcProtector protector, IMasterKeyProvider masterKeyProvider) {

            var clientDataJSON = ToClientDataJSON(origin, challenge);
            var clientDataHash = SHA256.Create().ComputeHash(clientDataJSON);
            var authenticatorData = new AuthenticatorData(RpId, ++SignCount).ToByteArray();
            var signature = RawSignatureToECDA(Sign(authenticatorData.Concat(clientDataHash).ToArray(), new NgcPin(protector.SignPin), masterKeyProvider, HashAlgorithmName.SHA256));
            var credId = Utils.Base64Url(CredentialId);

            File.WriteAllBytes(signCountPath, BitConverter.GetBytes(SignCount));

            return new PublicKeyCredential(credId, new AuthenticatorAssertionResponse(Utils.Base64Url(authenticatorData), Utils.Base64Url(clientDataJSON),
                Utils.Base64Url(signature), Utils.Base64Url(UserId)));
        }

        string StripQuotes(string str) {
            return str.Substring(1, str.Length - 2);
        }
    }
}
