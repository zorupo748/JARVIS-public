// TRUSTED TEST HELPER ONLY. No public destinations, credentials or DNS.
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

class Probe {
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int needed);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
    static IntPtr Info(IntPtr token, int kind) {
        int needed;
        GetTokenInformation(token, kind, IntPtr.Zero, 0, out needed);
        if (needed <= 0 || needed > 65536) throw new Exception("token_info_failed");
        IntPtr p = Marshal.AllocHGlobal(needed);
        if (!GetTokenInformation(token, kind, p, needed, out needed)) {
            Marshal.FreeHGlobal(p); throw new Exception("token_info_failed");
        }
        return p;
    }
    static string Identity() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 8, out token)) throw new Exception("token_open_failed");
        try {
            IntPtr data = Info(token, 29); // TokenIsAppContainer
            int isContainer = Marshal.ReadInt32(data); Marshal.FreeHGlobal(data);
            string result = "appcontainer=" + isContainer + "\n";
            data = Info(token, 30); // TokenCapabilities / TOKEN_GROUPS
            result += "capabilities=" + Marshal.ReadInt32(data) + "\n"; Marshal.FreeHGlobal(data);
            if (isContainer != 0) {
                data = Info(token, 31); // TokenAppContainerSid
                try {
                    IntPtr text;
                    if (!ConvertSidToStringSid(Marshal.ReadIntPtr(data), out text)) throw new Exception("sid_failed");
                    try { result += "sid=" + Marshal.PtrToStringUni(text) + "\n"; }
                    finally { LocalFree(text); }
                } finally { Marshal.FreeHGlobal(data); }
            } else { result += "sid=none\n"; }
            return result;
        } finally { CloseHandle(token); }
    }
    static string Attempt(string specification) {
        string[] parts = specification.Split(':');
        if (parts.Length != 2) return "invalid";
        bool v6 = parts[0].EndsWith("6");
        bool tcp = parts[0].StartsWith("tcp");
        if (parts[0] != "tcp4" && parts[0] != "udp4" && parts[0] != "tcp6" && parts[0] != "udp6") return "invalid";
        int port = int.Parse(parts[1]);
        if (port < 1 || port > 65535) return "invalid";
        IPEndPoint endpoint = new IPEndPoint(v6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, port);
        using (Socket socket = new Socket(v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork,
                                         tcp ? SocketType.Stream : SocketType.Dgram,
                                         tcp ? ProtocolType.Tcp : ProtocolType.Udp)) {
            socket.SendTimeout = 1000; socket.ReceiveTimeout = 1000;
            try {
                if (tcp) {
                    IAsyncResult pending = socket.BeginConnect(endpoint, null, null);
                    try {
                        if (!pending.AsyncWaitHandle.WaitOne(1000)) return "timeout";
                        socket.EndConnect(pending);
                    } finally { pending.AsyncWaitHandle.Close(); }
                    socket.Send(new byte[] {74,65,82,86,73,83});
                } else { socket.SendTo(new byte[] {74,65,82,86,73,83}, endpoint); }
                return tcp ? "connected" : "udp_sent"; // UDP send is NOT receipt.
            } catch (SocketException error) {
                return error.NativeErrorCode == 10013 ? "blocked_10013" : "error_" + error.NativeErrorCode;
            }
        }
    }
    static int Main(string[] args) {
#if PROBE_NO_REPORT
        return 7; // Test fixture for successful launch followed by helper failure.
#elif PROBE_HANG
        System.Threading.Thread.Sleep(10000);
        return 8; // Test fixture for supervisor timeout/termination cleanup.
#else
        try {
            if (args.Length < 2 || args.Length > 5) return 2;
            string report = Identity();
            for (int i=1; i<args.Length; i++) report += "endpoint_" + (i-1) + "=" + Attempt(args[i]) + "\n";
            File.WriteAllText(args[0], report, new System.Text.ASCIIEncoding());
            return 0;
        } catch { return 3; } // Explicit inconclusive, never simulated denial.
#endif
    }
}
