using CredProvider.NET.Interop2;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static CredProvider.NET.Constants;

namespace CredProvider.NET
{
    public abstract class CredentialProviderBase : ICredentialProvider, ICredentialProviderSetUserArray
    {
        private ICredentialProviderEvents events;

        protected abstract CredentialView Initialize(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint dwFlags);

        private CredentialView view;
        private _CREDENTIAL_PROVIDER_USAGE_SCENARIO usage;

        private List<ICredentialProviderUser> providerUsers;

        public virtual int SetUsageScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint dwFlags)
        {
            view = Initialize(cpus, dwFlags);
            usage = cpus;

            if (view.Active)
            {
                return HRESULT.S_OK;
            }

            return HRESULT.E_NOTIMPL;
        }

        public virtual int SetSerialization(ref _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs)
        {
            Logger.Write($"ulAuthenticationPackage: {pcpcs.ulAuthenticationPackage}");

            return HRESULT.S_OK;
        }

        public virtual int Advise(ICredentialProviderEvents pcpe, ulong upAdviseContext)
        {
            Logger.Write($"upAdviseContext: {upAdviseContext}");

            if (pcpe != null)
            {
                events = pcpe;

                Marshal.AddRef(Marshal.GetIUnknownForObject(pcpe));
            }

            return HRESULT.S_OK;
        }

        public virtual int UnAdvise()
        {
            Logger.Write();

            if (events != null)
            {
                //Marshal.Release(Marshal.GetIUnknownForObject(events));
                events = null;
            }

            return HRESULT.S_OK;
        }

        public virtual int GetFieldDescriptorCount(out uint pdwCount)
        {
            Logger.Write();

            pdwCount = (uint)view.DescriptorCount;

            Logger.Write($"Returning field count: {pdwCount}");

            return HRESULT.S_OK;
        }

        public virtual int GetFieldDescriptorAt(uint dwIndex, [Out] IntPtr ppcpfd)
        {
            if (view.GetField((int)dwIndex, ppcpfd))
            {
                return HRESULT.S_OK;
            }

            return HRESULT.E_INVALIDARG;
        }

        public virtual int GetCredentialCount(
            out uint pdwCount,
            out uint pdwDefault,
            out int pbAutoLogonWithDefault
        )
        {
            Logger.Write();

            pdwCount = (uint)providerUsers.Count;

            pdwDefault = (uint)view.DefaultCredential;

            if (pdwCount > 0)
            {
                var sessions = GetSessions();

                pdwDefault = (uint)providerUsers.FindIndex(
                    delegate (ICredentialProviderUser session)
                    {
                        session.GetSid(out var sid);
                        return sessions.Find(x => x.ToString().ToUpper() == sid.ToUpper()) != null;
                    }
                );
            }
            
            Logger.Write($"pdwDefault: {pdwDefault}");

            pbAutoLogonWithDefault = 0;

            return HRESULT.S_OK;
        }

        public virtual int GetCredentialAt(uint dwIndex, out ICredentialProviderCredential ppcpc)
        {
            Logger.Write($"dwIndex: {dwIndex}");

            ppcpc = view.CreateCredential((int)dwIndex);

            return HRESULT.S_OK;
        }

        public virtual _CREDENTIAL_PROVIDER_USAGE_SCENARIO GetUsage()
        {
            return usage;
        }

        public virtual int SetUserArray(ICredentialProviderUserArray users)
        {
            providerUsers = new List<ICredentialProviderUser>();

            users.GetCount(out uint count);
            users.GetAccountOptions(out CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options);

            Logger.Write($"count: {count}; options: {options}");

            for (uint i = 0; i < count; i++)
            {
                users.GetAt(i, out ICredentialProviderUser user);

                user.GetProviderID(out Guid providerId);
                user.GetSid(out string sid);

                providerUsers.Add(user);

                Logger.Write($"providerId: {providerId}; sid: {sid}");
            }

            return HRESULT.S_OK;
        }

        //Lookup the user by index and return the sid
        public virtual string GetUserSid(int dwIndex)
        {
            Logger.Write();

            //CredUI does not provide user sids, so return null
            if (this.providerUsers.Count < dwIndex + 1) return null;

            this.providerUsers[dwIndex].GetSid(out string sid);
            return sid;
        }

        private List<System.Security.Principal.SecurityIdentifier> GetSessions()
        {
            var sessions = new List<System.Security.Principal.SecurityIdentifier>();

            System.Security.Principal.WindowsIdentity currentUser = System.Security.Principal.WindowsIdentity.GetCurrent();

            // Win32 systemdate
            DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); 

            // Get an array of pointers to LUIDs
            PInvoke.LsaEnumerateLogonSessions(out UInt64 count, out IntPtr luidPtr);  

            IntPtr iter = luidPtr;

            for (ulong i = 0; i < count; i++)
            {
                IntPtr sessionData;

                PInvoke.LsaGetLogonSessionData(iter, out sessionData);
                var data = Marshal.PtrToStructure<PInvoke.SECURITY_LOGON_SESSION_DATA>(sessionData);
                
                // If we hace a valid logon
                if (data.PSiD != IntPtr.Zero)
                {
                    // Get the security identified for futher use
                    System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);

                    // Extract some useful information from the session data structure
                    string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                    string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                    string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();

                    PInvoke.SECURITY_LOGON_TYPE secType = (PInvoke.SECURITY_LOGON_TYPE)data.LogonType;

                    if (secType == PInvoke.SECURITY_LOGON_TYPE.Interactive && sid.IsAccountSid())
                    {
                        sessions.Add(sid);
                        DateTime time = systime.AddTicks((long)data.LoginTime);
                        Logger.Write($"User: {sid} Domain: {domain} Login Type: ({data.LogonType}) {secType.ToString()} Login Time: {time.ToLocalTime().ToString()}");
                    }
                }
                // Move the pointer forward
                iter = (IntPtr)((Int64)iter + Marshal.SizeOf(typeof(PInvoke.LUID)));

                // Free the SECURITY_LOGON_SESSION_DATA memory in the struct
                PInvoke.LsaFreeReturnBuffer(sessionData);
            }

            return sessions;
        }

    }
}
