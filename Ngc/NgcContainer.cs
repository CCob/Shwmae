using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using NtApiDotNet;
using DPAPI;
using Shwmae.Ngc.Keys;
using Shwmae.Ngc.Protectors;

namespace Shwmae.Ngc { 
  
    public class NgcContainer {

        public Guid Id { get; private set; }

        public Sid Sid { get; private set; }

        public string Provider { get; private set; }

        public string RecoveryKey { get; private set; }

        public IEnumerable<NgcProtector> Protectors { get; private set; }

        public IEnumerable<NgcKey> Keys { get; private set; }

        public string Path { get; private set; }

        public NgcContainer(string path) {
            Path = path;
            Id = Guid.Parse(System.IO.Path.GetFileName(path));
            Sid = Sid.Parse(NgcInterop.ReadNcgFileString(System.IO.Path.Combine(path, "1.dat")));
            Provider = NgcInterop.ReadNcgFileString(System.IO.Path.Combine(path, "7.dat"));            
            Protectors = NgcProtector.GetUserProtectors(this);
            Keys = NgcKey.GetNgcKeys(this);
            RecoveryKey = NgcInterop.ReadNcgFileString(System.IO.Path.Combine(path, "9.dat"));   
        }

        public static IEnumerable<NgcContainer> GetAll() {
            return Directory.GetDirectories(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"))
                .Select(userProtector => new NgcContainer(userProtector));
        }

        dynamic ResponseToObject(HttpResponseMessage response) {
            return JsonConvert.DeserializeObject<dynamic>(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        }

        public byte[] DecryptRecoveryKey(string accessToken, IMasterKeyProvider masterKeyProvider) {

            var credURL = $"https://cred.microsoft.com/unprotectsecret/v1";
            var httpClient = new HttpClient();
            
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var result = httpClient.PostAsync(credURL,
                new StringContent($@"{{""protectedSecret"":""{RecoveryKey}""}}", Encoding.UTF8, "application/json")).GetAwaiter().GetResult();

            if (!result.IsSuccessStatusCode) {
                var errorObject = ResponseToObject(result);
                throw new HttpRequestException($"Request to decrypt recovery key failed: {(int)result.StatusCode} ({errorObject.errorMessage})");
            }
                 
            var encryptedKey = DPAPI_BLOB.Parse(Convert.FromBase64String((string)ResponseToObject(result).secret));
            var masterKey = masterKeyProvider.GetMasterKey(encryptedKey.GuidMasterKey);

            if(masterKey == null) {
                throw new CryptographicException($"Failed to find master key with ID {encryptedKey.GuidMasterKey}");
            }

            return encryptedKey.Decrypt(masterKey.Key);
        }
    }
}
