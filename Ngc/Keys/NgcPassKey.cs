using System;
using System.IO;
using System.Security.Cryptography;
using Dahomey.Cbor;
using Dahomey.Cbor.ObjectModel;

namespace Shwmae.Ngc.Keys
{
    public class NgcPassKey : NgcKey
    {
        public string RpId { get; private set; }
        public string Name { get; private set; }
        public string DisplayName { get; private set; }
        public string UserId { get; private set; }
        public string CredentialId { get; private set; }

        public NgcPassKey(NgcContainer user, string path) : base(user, path)
        {

            var passkeyInfo = File.ReadAllBytes(Path.Combine(path, "7.dat"));
            var passkeyObj = Cbor.Deserialize<CborObject>(passkeyInfo);

            if (passkeyObj.TryGetValue(CborValueConvert.ToValue(2), out var rpInfo))
            {
                RpId = ((CborObject)rpInfo)[CborValueConvert.ToValue("id")].ToString();
            }

            if (passkeyObj.TryGetValue(CborValueConvert.ToValue(3), out var userInfo))
            {
                UserId = ((CborObject)userInfo)[CborValueConvert.ToValue("id")].ToString();
                Name = ((CborObject)userInfo)[CborValueConvert.ToValue("name")].ToString();
                DisplayName = ((CborObject)userInfo)[CborValueConvert.ToValue("displayName")].ToString();
            }

            using (var key = CngKey.Open(KeyId, new CngProvider(Provider))) {
                CredentialId = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPublicBlob));
            }
        }
    }
}
