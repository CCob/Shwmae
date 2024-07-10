using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using static BCrypt.PInvoke;
using System.Security.Cryptography;
using Shwmae;

namespace BCrypt {

    public class SafeBCryptAlgHandle : SafeBCryptHandle {

        public SafeBCryptAlgHandle() {

        }

        public SafeBCryptAlgHandle(bool ownsHandle) : base(ownsHandle) {
        }
        protected override bool ReleaseHandle() {
            BCryptCloseAlgorithmProvider(handle);
            SetHandleAsInvalid();
            return true;
        }
    }

    public class SafeBCryptKeyHandle : SafeBCryptHandle {

        public SafeBCryptKeyHandle() {

        }

        public SafeBCryptKeyHandle(bool ownsHandle) : base(ownsHandle) {
        }

        protected override bool ReleaseHandle() {
            BCryptDestroyKey(handle);
            SetHandleAsInvalid();
            return true;
        }

    }

    public abstract class SafeBCryptHandle : SafeHandleZeroOrMinusOneIsInvalid {

        public SafeBCryptHandle() : this(true) {

        }

        public SafeBCryptHandle(bool ownsHandle) : base(ownsHandle) {
        }

    }

    public static class PInvoke {
        public struct BCRYPT_KEY_LENGTHS_STRUCT {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
        }

        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            public uint cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;
        }       

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptSetProperty(SafeBCryptHandle hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptGetProperty(SafeBCryptHandle hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptOpenAlgorithmProvider(out SafeBCryptAlgHandle phAlgorithm, string pszAlgId, [Optional] string pszImplementation, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptGenerateSymmetricKey(SafeBCryptAlgHandle hAlgorithm, out SafeBCryptKeyHandle phKey, [Optional] IntPtr pbKeyObject, [Optional] uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptDecrypt(SafeBCryptKeyHandle hKey, byte[] pbInput, uint cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, uint cbIV, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptDestroyKey(IntPtr keyHandle);
    }

    public static class AESGCM {
    
        public static byte[] GcmDecrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null) {

            pbAuthData = pbAuthData ?? new byte[0];
            uint status;

            if (BCryptOpenAlgorithmProvider(out var provider, "AES") != 0) {
                throw new CryptographicException("Failed to open AES algorithm provider");
            }
            
            using (provider) {

                var tagLengthsData = new byte[Marshal.SizeOf<BCRYPT_KEY_LENGTHS_STRUCT>()];
                var chainingMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");

                if ((status = BCryptSetProperty(provider, "ChainingMode", chainingMode, (uint)chainingMode.Length)) != 0){
                    throw new CryptographicException($"Failed to set AES GCM chaining mode: 0x{status}");
                }

                var tagHandle = GCHandle.Alloc(tagLengthsData, GCHandleType.Pinned);

                try {                                        
                    if ((status = BCryptGetProperty(provider, "AuthTagLength", tagLengthsData, (uint)tagLengthsData.Length, out var result)) != 0) {
                        throw new CryptographicException($"Failed to get GCM auth tag length info: 0x{status}");
                    }

                    var tagLengths = tagHandle.AddrOfPinnedObject().ToStructure<BCRYPT_KEY_LENGTHS_STRUCT>();

                    if (pbTag.Length < tagLengths.dwMinLength
                                    || pbTag.Length > tagLengths.dwMaxLength
                                    || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                        throw new ArgumentException("Invalid tag length");

                } finally {
                    tagHandle.Free();
                }
            
                if(BCryptGenerateSymmetricKey(provider, out var keyHandle, IntPtr.Zero, 0, pbKey, (uint)pbKey.Length) != 0) {
                    throw new CryptographicException("Failed to import key");
                }
                
                using (keyHandle) {

                    var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();

                    var nonceHandle = GCHandle.Alloc(pbNonce, GCHandleType.Pinned);
                    var tagBufferHandle = GCHandle.Alloc(pbTag, GCHandleType.Pinned);
                    var authDataHandle = GCHandle.Alloc(pbAuthData, GCHandleType.Pinned);
                    
                    authInfo.cbSize = (uint)Marshal.SizeOf(authInfo);
                    authInfo.dwInfoVersion = 1;
                    authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                    authInfo.cbNonce = (uint)pbNonce.Length;
                    authInfo.pbTag = tagBufferHandle.AddrOfPinnedObject();
                    authInfo.cbTag = (uint)pbTag.Length;
                    authInfo.pbAuthData = authDataHandle.AddrOfPinnedObject();
                    authInfo.cbAuthData = (uint)pbAuthData.Length;
                  
                    int pcbPlaintext = pbData.Length;             
                    byte[] pbPlaintext = new byte[pcbPlaintext];

                    try {
                        if ((status = BCryptDecrypt(keyHandle, pbData, (uint)pbData.Length, ref authInfo, null, 0, pbPlaintext, (uint)pbPlaintext.Length, out var result, 0)) != 0) {
                            throw new CryptographicException($"Failed to decrypt data: 0x{status:x}");
                        }
                    } finally {
                        nonceHandle.Free();
                        tagBufferHandle.Free();
                        authDataHandle.Free();
                    }

                    return pbPlaintext;
                }                
            }                 
        }
    }
}
