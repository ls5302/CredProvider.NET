using System;
using System.Runtime.InteropServices;

namespace CredProvider.NET
{
    static class PInvoke
    {
        //http://www.pinvoke.net/default.aspx/secur32/LsaLogonUser.html
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public /*PCHAR*/ IntPtr Buffer;
        }

        public class LsaStringWrapper : IDisposable
        {
            public LSA_STRING _string;

            public LsaStringWrapper(string value)
            {
                _string = new LSA_STRING();
                _string.Length = (ushort)value.Length;
                _string.MaximumLength = (ushort)value.Length;
                _string.Buffer = Marshal.StringToHGlobalAnsi(value);
            }

            ~LsaStringWrapper()
            {
                Dispose(false);
            }

            private void Dispose(bool disposing)
            {
                if (_string.Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_string.Buffer);
                    _string.Buffer = IntPtr.Zero;
                }
                if (disposing)
                    GC.SuppressFinalize(this);
            }

            public void Dispose()
            {
                Dispose(true);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public LUID LoginID;
            public LSA_UNICODE_STRING Username;
            public LSA_UNICODE_STRING LoginDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
        }

        public enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,         // The security principal is logging on interactively. 
            Network,                 // The security principal is logging using a network. 
            Batch,                   // The logon is for a batch process. 
            Service,                 // The logon is for a service account. 
            Proxy,                   // Not supported. 
            Unlock,                  // The logon is an attempt to unlock a workstation.
            NetworkCleartext,        // The logon is a network logon with cleartext credentials.
            NewCredentials,          // Allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identity but uses different credentials for other network connections.
            RemoteInteractive,       // A terminal server session that is both remote and interactive.
            CachedInteractive,       // Attempt to use the cached credentials without going out across the network.
            CachedRemoteInteractive, // Same as RemoteInteractive, except used internally for auditing purposes.
            CachedUnlock             // The logon is an attempt to unlock a workstation.
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaConnectUntrusted([Out] out IntPtr lsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaLookupAuthenticationPackage([In] IntPtr lsaHandle, [In] ref LSA_STRING packageName, [Out] out UInt32 authenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaDeregisterLogonProcess([In] IntPtr lsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaEnumerateLogonSessions([Out] out UInt64 logonSessionCount, [Out] out IntPtr logonSessionList);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaGetLogonSessionData([In] IntPtr LogonId, [Out] out IntPtr ppLogonSessionData);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer([In] IntPtr buffer);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredPackAuthenticationBuffer(
            int dwFlags,
            string pszUserName,
            string pszPassword,
            IntPtr pPackedCredentials,
            ref int pcbPackedCredentials
        );
    }
}
