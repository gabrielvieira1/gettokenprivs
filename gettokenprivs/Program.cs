using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace gettokenprivs
{
  internal class Program
  {
    public enum TOKEN_INFORMATION_CLASS
    {
      TokenUser = 1,
      TokenGroups,
      TokenPrivileges,
      TokenOwner,
      TokenPrimaryGroup,
      TokenDefaultDacl,
      TokenSource,
      TokenType,
      TokenImpersonationLevel,
      TokenStatistics,
      TokenRestrictedSids,
      TokenSessionId,
      TokenGroupsAndPrivileges,
      TokenSessionReference,
      TokenSandBoxInert,
      TokenAuditPolicy,
      TokenOrigin,
      TokenElevationType,
      TokenLinkedToken,
      TokenElevation,
      TokenHasRestrictions,
      TokenAccessInformation,
      TokenVirtualizationAllowed,
      TokenVirtualizationEnabled,
      TokenIntegrityLevel,
      TokenUIAccess,
      TokenMandatoryPolicy,
      TokenLogonSid,
      TokenIsAppContainer,
      TokenCapabilities,
      TokenAppContainerSid,
      TokenAppContainerNumber,
      TokenUserClaimAttributes,
      TokenDeviceClaimAttributes,
      TokenRestrictedUserClaimAttributes,
      TokenRestrictedDeviceClaimAttributes,
      TokenDeviceGroups,
      TokenRestrictedDeviceGroups,
      TokenSecurityAttributes,
      TokenIsRestricted,
      TokenProcessTrustLevel,
      TokenPrivateNameSpace,
      TokenSingletonAttributes,
      TokenBnoIsolation,
      TokenChildProcessFlags,
      TokenIsLessPrivilegedAppContainer,
      TokenIsSandboxed,
      TokenIsAppSilo,
      MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public uint LowPart;
      public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
      public LUID Luid;
      public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
      public uint PrivilegeCount;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)]
      LUID_AND_ATTRIBUTES[] Privileges;
    }


    [DllImport("Advapi32.dll")]
    public static extern bool OpenProcessToken(
      IntPtr ProcessHandle,
      int DesiredAccess,
      ref IntPtr TokenHandle
      );

    [DllImport("Advapi32.dll")]
    public static extern bool GetTokenInformation(
      IntPtr TokenHandle,
      TOKEN_INFORMATION_CLASS TokenInformationClass,
      IntPtr TokenInformation,
      int TokenInformationLength,
      ref int ReturnLength
      );

    [DllImport("Kernel32.dll")]
    public static extern bool CloseHandle(IntPtr phandle);

    [DllImport("Advapi32.dll")]
    public static extern bool LookupPrivilegeNameW(
      string lpSystemName,
      IntPtr lpLuid,
      [param:MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpName,
      ref int cchName
      );

    static void Main(string[] args)
    {
      int TOKEN_QUERY = 0x0008;
      IntPtr tokenHandle = IntPtr.Zero;
      IntPtr procHanle = Process.GetCurrentProcess().Handle;

      bool res = OpenProcessToken(procHanle, TOKEN_QUERY, ref tokenHandle);

      int privlength = 0;
      GetTokenInformation(
        tokenHandle,
        TOKEN_INFORMATION_CLASS.TokenPrivileges,
        IntPtr.Zero,
        privlength,
        ref privlength
        );

      Console.WriteLine(privlength);

      IntPtr tpptr = Marshal.AllocHGlobal(privlength);

      GetTokenInformation(
        tokenHandle,
        TOKEN_INFORMATION_CLASS.TokenPrivileges,
        tpptr,
        privlength,
        ref privlength
        );

      TOKEN_PRIVILEGES tp = (TOKEN_PRIVILEGES) Marshal.PtrToStructure(tpptr, typeof(TOKEN_PRIVILEGES));

      Console.WriteLine(tp.PrivilegeCount);

      IntPtr startingptr = new IntPtr(tpptr.ToInt64() + sizeof(uint));
      LUID_AND_ATTRIBUTES laa2 = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(startingptr, typeof(LUID_AND_ATTRIBUTES));


      for (int i = 0; i < tp.PrivilegeCount; i++)
      {
        IntPtr tempptr = new IntPtr(startingptr.ToInt64() +(i* Marshal.SizeOf(laa2)));
        LUID_AND_ATTRIBUTES laa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(tempptr, typeof(LUID_AND_ATTRIBUTES));

        Console.WriteLine(laa.Luid.LowPart);
        Console.WriteLine(laa.Luid.HighPart);

        int cchName = 100;
        StringBuilder sb = new StringBuilder();

        IntPtr luidptr = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
        Marshal.StructureToPtr(laa.Luid, luidptr, true);

        LookupPrivilegeNameW(
          null,
          luidptr,
          sb,
          ref cchName
          );

        Console.WriteLine(sb.ToString());
      }

      CloseHandle(tokenHandle);

      Console.WriteLine("Press any Key to continue");
      Console.ReadLine();
    }
  }
}