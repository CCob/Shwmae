using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Shwmae.Fido2 {
    public class AuthenticatorAssertionResponse {

        public string AuthenticatorData;
        public string ClientDataJSON;
        public string Signature;
        public string UserHandle;

        public AuthenticatorAssertionResponse(string authData, string clientDataJSON, string signature, string userHandle) {
            AuthenticatorData = authData;
            ClientDataJSON = clientDataJSON;
            Signature = signature;
            UserHandle = userHandle;
        }
    }
}
