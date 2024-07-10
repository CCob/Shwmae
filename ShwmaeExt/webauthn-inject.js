// content.js

const browserCredentials = {
    create: navigator.credentials.create.bind(
      navigator.credentials,
    ) ,
    get: navigator.credentials.get.bind(navigator.credentials),
  };

navigator.credentials.get = getWebAuthnCredential;

function base64URLdecode(str) {
    const base64Encoded = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
    const base64WithPadding = base64Encoded + padding;
    var binaryString = atob(base64WithPadding)
      .split('')
      .map(char => String.fromCharCode(char.charCodeAt(0)))
      .join('');

    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

async function getWebAuthnCredential(options) {

    //var response = await browserCredentials.get(options)
    //return response;

    // The ID of the extension we want to talk to.
    var editorExtensionId = "ijacbjjjpmhencpkoghphdgbooifplmn";

    var assertion = await chrome.runtime.sendMessage(editorExtensionId, {type: 'getCredential', value: JSON.stringify({origin: window.location.origin, options: options}, function(k, v){
        if(v instanceof ArrayBuffer){
            return btoa(String.fromCharCode.apply(null, new Uint8Array(v)));
        }
        return v;
    })});   
    
    var assertionConverted = {
        id: assertion.id,
        rawId: base64URLdecode(assertion.rawId),
        response: {
            authenticatorData: base64URLdecode(assertion.result.authenticatorData),
            clientDataJSON: base64URLdecode(assertion.result.clientDataJSON),
            signature: base64URLdecode(assertion.result.signature),
            userHandle: base64URLdecode(assertion.result.userHandle)
        },
        type: assertion.type,
        clientExtensionResults: assertion.clientExtensionResults,
        authenticatorAttachment: assertion.authenticatorAttachment,
        
        getClientExtensionResults: function(){
            return this.clientExtensionResults;
        }
    }   
    
    return assertionConverted;
};


