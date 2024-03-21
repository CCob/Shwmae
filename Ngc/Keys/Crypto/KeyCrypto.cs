using System.Security.Cryptography;
using DPAPI;

namespace Shwmae.Ngc.Keys.Crypto
{
    public interface KeyCrypto
    {
        byte[] Sign(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider, HashAlgorithmName alg);
        byte[] Decrypt(byte[] data, NgcPin pin, IMasterKeyProvider masterKeyProvider);
    }
}
