using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Shwmae.Fido2 {
    public class PublicKeyCredential {

        public string Id;
        public string RawId;
        public string Type;
        public object[] ClientExtensionResults = new object[0];
        public string AuthenticatorAttachement;
        public AuthenticatorAssertionResponse Result;

        public PublicKeyCredential(string id, AuthenticatorAssertionResponse result) {
            Id = id;
            RawId = id;
            Type = "public-key";
            AuthenticatorAttachement = "platform";
            Result = result;
        }
    }
}
