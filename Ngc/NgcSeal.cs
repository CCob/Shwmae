using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Shwmae.Ngc {
    public class NgcSeal {

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct UnkPin {
            public uint Length;
            public uint UnkFlag;
            public string Pin;
            public UnkPin(NgcPin pin) {
                Pin = pin.ToString() + "\0";
                Length = (uint)Pin.Length * 2;
                UnkFlag = 0x46;                
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UnkPadding : IDisposable {
            public UnkPin UnkPin { get; private set; }
            IntPtr ptr;
            GCHandle handle;
            byte[] unkPinBytes;

            public UnkPadding(UnkPin unkPin) {
                UnkPin = unkPin;
                unkPinBytes = unkPin.ToBytes();
                handle = GCHandle.Alloc(unkPinBytes, GCHandleType.Pinned);
                ptr = handle.AddrOfPinnedObject();
            }

            public void Dispose() {
                if(handle != default) { 
                    handle.Free();
                    handle = default;
                    ptr = IntPtr.Zero;
                }                
                GC.SuppressFinalize(this);
            }
            
            public byte[] ToBytes() {
                using (var br = new BinaryWriter(new MemoryStream())) {

                    br.Write(0);
                    br.Write(1);
                    if(IntPtr.Size == 8)
                        br.Write((ulong)ptr);
                    else
                        br.Write((uint)ptr);
                    
                    return ((MemoryStream)br.BaseStream).ToArray();
                }

            }
        }

        static readonly string TPM_RSA_SRK_SEAL_KEY = "MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074";
        static CngProvider cngProvider;

        static NgcSeal() {
            cngProvider = new CngProvider("Microsoft Platform Crypto Provider");
        }

        public static byte[] Unseal(byte[] data, NgcPin pin) {

            using (UnkPadding unkPadding = new UnkPadding(new UnkPin(pin))) {
                using (var sealKey = CngKey.Open(TPM_RSA_SRK_SEAL_KEY, cngProvider, CngKeyOpenOptions.Silent)) {

                    SECURITY_STATUS status;

                    if ((status = NgcInterop.NCryptDecrypt(sealKey.Handle, data, data.Length, unkPadding.ToBytes(), null, 0, out int outputSize, NCryptEncryptFlags.NCRYPT_SEALING_FLAG)) != SECURITY_STATUS.ERROR_SUCCESS) {
                        throw new CryptographicException($"Failed to determine unseal data length: {status}");
                    }

                    byte[] result = new byte[outputSize];

                    if ((status = NgcInterop.NCryptDecrypt(sealKey.Handle, data, data.Length, unkPadding.ToBytes(), result, result.Length, out outputSize, NCryptEncryptFlags.NCRYPT_SEALING_FLAG)) != SECURITY_STATUS.ERROR_SUCCESS) {
                        throw new CryptographicException($"Failed to unseal data: {status}");
                    }

                    return result;
                }
            }
        }
    }
}
