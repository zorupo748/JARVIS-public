// PUBLIC TEST HELPER. No credentials stored, no DNS, no rule/account changes.
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.IO;
using System.Collections.Generic;

class SIDFirewallProbe {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
  public int cb; public string reserved,desktop,title; public int x,y,cx,cy,xc,yc,fill,flags;
  public short show,cbReserved; public IntPtr reserved2,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr process,thread;public int pid,tid;}
 [StructLayout(LayoutKind.Sequential)] struct Basic {
  public long processTime,jobTime;public uint flags;public UIntPtr minWS,maxWS;public uint active;
  public UIntPtr affinity;public uint priority,scheduling;
 }
 [StructLayout(LayoutKind.Sequential)] struct Extended {
  public Basic basic;public ulong rOps,wOps,oOps,rBytes,wBytes,oBytes;
  public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
 }
 [StructLayout(LayoutKind.Sequential)] struct Accounting {
  public long totalUser,totalKernel,periodUser,periodKernel;
  public uint pageFaults,totalProcesses,activeProcesses,terminatedProcesses;
 }
 [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
  public int length;public IntPtr descriptor;[MarshalAs(UnmanagedType.Bool)]public bool inherit;
 }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessWithLogonW(string u,string d,string p,int logon,string app,StringBuilder args,int flags,IntPtr env,string cwd,ref Startup s,out ProcessInfo pi);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,int access,out IntPtr token);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int kind,ref Extended data,int size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool yes);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr j,int code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,int code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,int ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h,out int code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int kind,ref Accounting data,int size,IntPtr needed);
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] static extern bool JobPids(IntPtr j,int kind,[Out] byte[] data,int size,IntPtr needed);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr h,int mask,int flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(int access,bool inherit,int pid);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool RevertToSelf();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 class Failure:Exception {public string stage;public int code;public Failure(string s,int c){stage=s;code=c;}}
 static void Require(bool ok,string stage) {if(!ok) throw new Failure(stage,Marshal.GetLastWin32Error());}
 static void Diagnostic(string stage,int code) {Console.WriteLine("diag="+stage+","+code);}
 static void WaitChecked(IntPtr handle,int ms,string stage) {
  uint result=WaitForSingleObject(handle,ms);
  if(result==UInt32.MaxValue) throw new Failure(stage,Marshal.GetLastWin32Error());
  if(result!=0) throw new Failure(stage+"_timeout",0);
 }
 static bool Identity(WindowsIdentity id,string expected) {
  if(id.User.Value!=expected) return false;
  foreach(IdentityReference g in id.Groups) if(g.Value=="S-1-5-32-544") return false;
  return true; // Includes deny-only admin membership, not just elevated role.
 }
 static bool Self(string sid) {
  bool job; using(WindowsIdentity id=WindowsIdentity.GetCurrent())
   return Identity(id,sid) && IsProcessInJob(Process.GetCurrentProcess().Handle,IntPtr.Zero,out job) && job;
 }
 static int Attempt(string spec) {
  string[] parts=spec.Split(','); if(parts.Length!=3) return 4;
  IPAddress ip=IPAddress.Parse(parts[1]);int port=int.Parse(parts[2]);bool tcp=parts[0]=="tcp";
  byte[] marker=Encoding.ASCII.GetBytes("JARVIS-SID-LAB");
  using(Socket s=new Socket(ip.AddressFamily,tcp?SocketType.Stream:SocketType.Dgram,tcp?ProtocolType.Tcp:ProtocolType.Udp)) {
   s.SendTimeout=1000;s.ReceiveTimeout=1000;
   try {
    IPEndPoint endpoint=new IPEndPoint(ip,port);
    if(tcp) {
     IAsyncResult pending=s.BeginConnect(endpoint,null,null);
     try {if(!pending.AsyncWaitHandle.WaitOne(1000)) return 3;s.EndConnect(pending);}
     finally {pending.AsyncWaitHandle.Close();}
     s.Send(marker);
    } else {s.Connect(endpoint);s.Send(marker);}
    byte[] reply=new byte[marker.Length];int count=s.Receive(reply);
    if(count!=marker.Length) return 4;
    for(int i=0;i<count;i++) if(reply[i]!=marker[i]) return 4;
    return 1; // Echo actually received, UDP send alone never success.
   } catch(SocketException e) {return e.NativeErrorCode==10013?2:e.SocketErrorCode==SocketError.TimedOut?3:4;}
  }
 }
 static int Probe(string sid,string[] specs) {
  if(!Self(sid)) return 97;
  int packed=1<<30;
  string executable=Process.GetCurrentProcess().MainModule.FileName;
  for(int i=0;i<specs.Length;i++) {
   try {
   ProcessStartInfo info=new ProcessStartInfo(executable,"child "+sid+" "+specs[i]);
   info.UseShellExecute=false;info.CreateNoWindow=true;
   using(Process child=Process.Start(info)) {
    if(!child.WaitForExit(3000)) {child.Kill();child.WaitForExit(3000);return packed;}
    int code=child.ExitCode;
    if(code<65 || code>68) return packed;
    packed|=(code-64)<<(3*i);
    packed=(packed & ~(15<<26))|((i+1)<<26);
   }
   } catch {return packed;} // Keep already verified child attempts; parent diagnoses incomplete probe.
  }
  return packed;
 }
 static int Launch(string[] args) {
  IntPtr job=IntPtr.Zero;ProcessInfo pi=new ProcessInfo();bool empty=false,rootStopped=true,handlesClosed=true;
  string stage="job_create";
  Console.WriteLine("report_version=2");
  try {
   job=CreateJobObject(IntPtr.Zero,null);Require(job!=IntPtr.Zero,stage);
   Extended limits=new Extended();limits.basic.flags=0x2000; // kill-on-close, NO breakaway
   stage="job_limits";Require(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(Extended))),stage);
   string password=Console.ReadLine();
   string exe=Process.GetCurrentProcess().MainModule.FileName;
   string command="\""+exe+"\" probe "+args[2];
   for(int i=4;i<args.Length;i++) command+=" "+args[i];
   stage="process_create";if(command.Length>1023) throw new Failure(stage,0);
   Startup s=new Startup();s.cb=Marshal.SizeOf(typeof(Startup));
   // Zero logon flags: neither load profile nor network-only impersonation.
   bool created=CreateProcessWithLogonW(args[1],Environment.MachineName,password,0,exe,new StringBuilder(command),0x08000004,IntPtr.Zero,Environment.GetFolderPath(Environment.SpecialFolder.System),ref s,out pi);
   password=null;Require(created,stage);rootStopped=false;
   Console.WriteLine("process_created=1");Console.WriteLine("root_pid="+pi.pid);
   stage="job_assign";Require(AssignProcessToJobObject(job,pi.process),stage);
   IntPtr token;
   stage="token_open";Require(OpenProcessToken(pi.process,8,out token),stage);
   try {stage="root_identity";using(WindowsIdentity id=new WindowsIdentity(token)) {if(!Identity(id,args[2])) throw new Failure(stage,0);}}
   finally {if(!CloseHandle(token)) {handlesClosed=false;Diagnostic("close_token",Marshal.GetLastWin32Error());}}
   Console.WriteLine("root_identity=1");
   bool inJob;stage="root_job";Require(IsProcessInJob(pi.process,job,out inJob),stage);if(!inJob) throw new Failure(stage,0);
   Console.WriteLine("root_in_job=1");
   stage="resume";Require(ResumeThread(pi.thread)!=UInt32.MaxValue,stage);
   stage="wait";WaitChecked(pi.process,int.Parse(args[3]),stage);rootStopped=true;Console.WriteLine("root_exited=1");
   int exit;stage="exit_code";Require(GetExitCodeProcess(pi.process,out exit),stage);
   Console.WriteLine("root_exit_code="+exit);
   stage="probe_result";if((exit&(1<<30))==0) throw new Failure(stage,0);
   int count=(exit>>26)&15;if(count>args.Length-4) throw new Failure(stage,0);
   if(count==args.Length-4) Console.WriteLine("child_identity=1");
   string[] outcomes={"error","echo_received","denied_10013","timeout","error"};
   for(int i=0;i<count;i++) {int value=(exit>>(3*i))&7;Console.WriteLine("child_verified="+i);Console.WriteLine("attempt="+(value<outcomes.Length?outcomes[value]:"error"));}
   if(count!=args.Length-4) Diagnostic("probe_incomplete",0);
  } catch(Failure failure) {Diagnostic(failure.stage,failure.code);}
    catch {Diagnostic(stage,0);}
  finally {
   if(pi.process!=IntPtr.Zero && !rootStopped) {
    if(!TerminateProcess(pi.process,100)) Diagnostic("terminate_root",Marshal.GetLastWin32Error());
    uint wait=WaitForSingleObject(pi.process,3000);rootStopped=wait==0;
    if(!rootStopped) Diagnostic("cleanup_wait",wait==UInt32.MaxValue?Marshal.GetLastWin32Error():0);
   }
   Console.WriteLine("root_stopped="+(rootStopped?"1":"0"));
   if(job!=IntPtr.Zero) {
    if(!TerminateJobObject(job,100)) Diagnostic("terminate_job",Marshal.GetLastWin32Error());
    for(int i=0;i<30;i++) {Accounting data=new Accounting();
     if(!QueryInformationJobObject(job,1,ref data,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)) {Diagnostic("job_query",Marshal.GetLastWin32Error());break;}
     if(data.activeProcesses==0) {empty=true;break;}
     Thread.Sleep(100);
    }
    if(!empty) Diagnostic("job_not_empty",0);
   } else {empty=pi.process==IntPtr.Zero;}
   if(pi.thread!=IntPtr.Zero && !CloseHandle(pi.thread)) {handlesClosed=false;Diagnostic("close_thread",Marshal.GetLastWin32Error());}
   if(pi.process!=IntPtr.Zero && !CloseHandle(pi.process)) {handlesClosed=false;Diagnostic("close_process",Marshal.GetLastWin32Error());}
   if(job!=IntPtr.Zero && !CloseHandle(job)) {handlesClosed=false;Diagnostic("close_job",Marshal.GetLastWin32Error());}
   Console.WriteLine("job_empty="+(empty?"1":"0"));
   Console.WriteLine("handles_closed="+(handlesClosed?"1":"0"));
  }
  return 0;
 }
 static int ChromiumLaunch(string[] args) {
  IntPtr job=IntPtr.Zero;ProcessInfo pi=new ProcessInfo();bool empty=false,stopped=true,closed=true;
  string stage="job_create";FileStream output=null,error=null;
  IntPtr input=IntPtr.Zero,environment=IntPtr.Zero;
  HashSet<int> observed=new HashSet<int>();long peak=0;bool inspectionFailed=false;int networkCount=0;
  Console.WriteLine("chromium_report=1");
  try {
   job=CreateJobObject(IntPtr.Zero,null);Require(job!=IntPtr.Zero,stage);
   Extended limits=new Extended();limits.basic.flags=0x2000;
   stage="job_limits";Require(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(Extended))),stage);
   stage="stdio_setup";
   output=new FileStream(args[7],FileMode.CreateNew,FileAccess.Write,FileShare.ReadWrite);
   error=new FileStream(args[8],FileMode.CreateNew,FileAccess.Write,FileShare.ReadWrite);
   Require(SetHandleInformation(output.SafeFileHandle.DangerousGetHandle(),1,1),stage);
   Require(SetHandleInformation(error.SafeFileHandle.DangerousGetHandle(),1,1),stage);
   SecurityAttributes security=new SecurityAttributes();security.length=Marshal.SizeOf(typeof(SecurityAttributes));security.inherit=true;
   IntPtr securityBuffer=Marshal.AllocHGlobal(security.length);
   try {Marshal.StructureToPtr(security,securityBuffer,false);input=CreateFile("NUL",0x80000000u,7,securityBuffer,3,0,IntPtr.Zero);Require(input!=new IntPtr(-1),stage);}
   finally {Marshal.FreeHGlobal(securityBuffer);}
   string password=Console.ReadLine();
   // Explicit inherited output handles; INVALID stdin must not influence
   // Chromium startup. Use an inheritable NUL handle, not the credential pipe.
   // Only trusted synthetic data: HTML. No remote debug port or sandbox bypass.
   string command="\""+args[4]+"\" --headless --dump-dom --no-first-run --disable-background-networking --disable-quic --disable-component-update --disable-sync --timeout=5000 --virtual-time-budget=1000 --user-data-dir=\""+args[5]+"\" \"data:text/html;base64,"+args[6]+"\"";
   stage="process_create";if(command.Length>1023) throw new Failure(stage,0);
   Startup startup=new Startup();startup.cb=Marshal.SizeOf(typeof(Startup));startup.flags=0x100;
   startup.input=input;
   startup.output=output.SafeFileHandle.DangerousGetHandle();startup.error=error.SafeFileHandle.DangerousGetHandle();
   string temporary=Path.Combine(args[5],"Temp");Directory.CreateDirectory(temporary);
   string local=Path.Combine(args[5],"LocalAppData");Directory.CreateDirectory(local);
   string roaming=Path.Combine(args[5],"AppData");Directory.CreateDirectory(roaming);
   string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   string[] entries={"SystemRoot="+windows,"WINDIR="+windows,"PATH="+Path.Combine(windows,"System32"),"TEMP="+temporary,"TMP="+temporary,"USERPROFILE="+args[5],"LOCALAPPDATA="+local,"APPDATA="+roaming};
   Array.Sort(entries,StringComparer.OrdinalIgnoreCase);string block=String.Join("\0",entries)+"\0\0";
   environment=Marshal.StringToHGlobalUni(block);
   bool created=CreateProcessWithLogonW(args[1],Environment.MachineName,password,0,args[4],new StringBuilder(command),0x08000404,environment,args[5],ref startup,out pi);
   password=null;Require(created,stage);stopped=false;
   Console.WriteLine("process_created=1");Console.WriteLine("root_pid="+pi.pid);
   stage="job_assign";Require(AssignProcessToJobObject(job,pi.process),stage);
   IntPtr token;stage="token_open";Require(OpenProcessToken(pi.process,8,out token),stage);
   try {stage="root_identity";using(WindowsIdentity identity=new WindowsIdentity(token)) {if(!Identity(identity,args[2])) throw new Failure(stage,0);}}
   finally {if(!CloseHandle(token)) {closed=false;Diagnostic("close_token",Marshal.GetLastWin32Error());}}
   Console.WriteLine("root_identity=1");bool yes;stage="root_job";Require(IsProcessInJob(pi.process,job,out yes),stage);if(!yes)throw new Failure(stage,0);
   Console.WriteLine("root_in_job=1");stage="resume";Require(ResumeThread(pi.thread)!=UInt32.MaxValue,stage);
   Stopwatch timer=Stopwatch.StartNew();
   while(timer.ElapsedMilliseconds<int.Parse(args[3])) {
    stage="process_inspection";
    // Local WMI tree sampling supplements observed parent IDs. Keep observed
    // parent IDs so short-lived parents do not erase known descendants.
    HashSet<int> family=new HashSet<int>(observed);family.Add(pi.pid);
    using(var search=new System.Management.ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,CommandLine,Name FROM Win32_Process")) {
     search.Options.Timeout=TimeSpan.FromSeconds(1);
     using(var rows=search.Get()) {
      List<System.Management.ManagementObject> list=new List<System.Management.ManagementObject>();
      foreach(System.Management.ManagementObject row in rows) list.Add(row);
      for(int pass=0;pass<4;pass++) foreach(var row in list) if(family.Contains(Convert.ToInt32(row["ParentProcessId"]))) family.Add(Convert.ToInt32(row["ProcessId"]));
      long ws=0;
      foreach(var row in list) {
       int pid=Convert.ToInt32(row["ProcessId"]);if(!family.Contains(pid))continue;
       string commandLine=row["CommandLine"] as string;
       string role=pid==pi.pid?"browser":commandLine==null?"unknown":commandLine.Contains("--type=renderer")?"renderer":commandLine.Contains("--type=gpu-process")?"gpu":commandLine.Contains("NetworkService")?"network":commandLine.Contains("--type=utility")?"utility":"other";
       // VM_READ is not required for token/Job inspection and could itself
       // deny access to sandboxed children. Preserve unknown token results.
       IntPtr handle=pid==pi.pid?pi.process:OpenProcess(0x1000,false,pid);bool identity=false,membership=false;int diagnostic=0;
       if(handle==IntPtr.Zero) {diagnostic=Marshal.GetLastWin32Error();Console.WriteLine("inspection_diag="+pid+",open_process,"+diagnostic);}
       else {
        try {
         IntPtr tok;if(OpenProcessToken(handle,8,out tok)) {
          try {using(WindowsIdentity id=new WindowsIdentity(tok))identity=Identity(id,args[2]);}
          finally {CloseHandle(tok);}
         } else {diagnostic=Marshal.GetLastWin32Error();Console.WriteLine("inspection_diag="+pid+",token_open,"+diagnostic);}
         if(!IsProcessInJob(handle,job,out membership)){diagnostic=Marshal.GetLastWin32Error();Console.WriteLine("inspection_diag="+pid+",job_membership,"+diagnostic);}
         try {using(Process process=Process.GetProcessById(pid))ws+=process.WorkingSet64;} catch {Console.WriteLine("inspection_diag="+pid+",memory_sample,0");}
        } finally {if(pid!=pi.pid)CloseHandle(handle);}
       }
       if(observed.Add(pid)) {if(role=="network")networkCount++;Console.WriteLine("process="+pid+","+role+","+(identity?"1":"0")+","+(membership?"1":"0")+","+diagnostic);}
       if(!identity || !membership || diagnostic!=0)inspectionFailed=true;
      }
      foreach(var row in list)row.Dispose();if(ws>peak)peak=ws;
     }
    }
    stage="wait";uint wait=WaitForSingleObject(pi.process,200);
    if(wait==0) {stopped=true;break;}
    if(wait==UInt32.MaxValue)throw new Failure("wait",Marshal.GetLastWin32Error());
   }
   if(!stopped)throw new Failure("wait_timeout",0);
   Console.WriteLine("root_exited=1");int exit;stage="exit_code";Require(GetExitCodeProcess(pi.process,out exit),stage);
   Console.WriteLine("root_exit_code="+exit);
   Accounting accounting=new Accounting();stage="job_query";Require(QueryInformationJobObject(job,1,ref accounting,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero),stage);
  } catch(Failure failure) {Diagnostic(failure.stage,failure.code);} catch {Diagnostic(stage,0);inspectionFailed=true;}
  finally {
   Console.WriteLine("sampled_peak_ws="+peak);Console.WriteLine("inspection_failed="+(inspectionFailed?"1":"0"));
   Console.WriteLine("network_process_count="+networkCount);
   if(pi.process!=IntPtr.Zero&&!stopped) {if(!TerminateProcess(pi.process,100))Diagnostic("terminate_root",Marshal.GetLastWin32Error());stopped=WaitForSingleObject(pi.process,3000)==0;}
   Console.WriteLine("root_stopped="+(stopped?"1":"0"));
   if(job!=IntPtr.Zero) {
    Accounting measured=new Accounting();
    if(QueryInformationJobObject(job,1,ref measured,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))Console.WriteLine("cpu_ms="+((measured.totalUser+measured.totalKernel)/10000));
    if(!TerminateJobObject(job,100))Diagnostic("terminate_job",Marshal.GetLastWin32Error());
    for(int i=0;i<30;i++) {Accounting data=new Accounting();if(!QueryInformationJobObject(job,1,ref data,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)){Diagnostic("job_query",Marshal.GetLastWin32Error());break;}if(data.activeProcesses==0){empty=true;break;}Thread.Sleep(100);}
   } else empty=pi.process==IntPtr.Zero;
   if(pi.thread!=IntPtr.Zero&&!CloseHandle(pi.thread)){closed=false;Diagnostic("close_thread",Marshal.GetLastWin32Error());}
   if(pi.process!=IntPtr.Zero&&!CloseHandle(pi.process)){closed=false;Diagnostic("close_process",Marshal.GetLastWin32Error());}
   if(job!=IntPtr.Zero&&!CloseHandle(job)){closed=false;Diagnostic("close_job",Marshal.GetLastWin32Error());}
   if(output!=null)output.Dispose();if(error!=null)error.Dispose();
   if(input!=IntPtr.Zero&&input!=new IntPtr(-1)&&!CloseHandle(input)){closed=false;Diagnostic("close_stdin",Marshal.GetLastWin32Error());}
   if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);
   Console.WriteLine("job_empty="+(empty?"1":"0"));Console.WriteLine("handles_closed="+(closed?"1":"0"));
  }
  return 0;
 }
 static int EnvironmentAccess(string[] args) {
  IntPtr token=IntPtr.Zero;bool impersonated=false;string stage="credential_logon";
  try {
   string password=Console.ReadLine();bool logged=LogonUser(args[1],Environment.MachineName,password,2,0,out token);
   password=null;Require(logged,stage);Console.WriteLine("credential_logon=1");
   stage="root_identity";using(WindowsIdentity id=new WindowsIdentity(token)){if(!Identity(id,args[2]))throw new Failure(stage,0);}
   Console.WriteLine("root_identity=1");stage="impersonate";Require(ImpersonateLoggedOnUser(token),stage);impersonated=true;
   for(int i=0;i<8;i++) {
    string path=args[3+i/2];uint access=i%2==1?0x40000000u:i<4?0xA0000000u:0x80000000u;
    IntPtr handle=CreateFile(path,access,7,IntPtr.Zero,3,0,IntPtr.Zero);
    int code=handle==new IntPtr(-1)?Marshal.GetLastWin32Error():0;
    if(code==0)CloseHandle(handle);
    Console.WriteLine("environment_access="+i+","+code);
   }
   int count;if(!Int32.TryParse(Console.ReadLine(),out count)||count<1||count>50000)throw new Failure("repository_access",0);
   bool denied=true;
   for(int i=0;i<count;i++) {
    string path=Console.ReadLine();
    if(path==null||!Path.GetFullPath(path).StartsWith("E:\\JARVIS\\",StringComparison.OrdinalIgnoreCase))throw new Failure("repository_access",0);
    foreach(uint access in new uint[]{0x80000000u,0x40000000u}) {
     IntPtr handle=CreateFile(path,access,7,IntPtr.Zero,3,0,IntPtr.Zero);
     int code=handle==new IntPtr(-1)?Marshal.GetLastWin32Error():0;
     if(code==0)CloseHandle(handle);if(code!=5)denied=false;
    }
   }
   Console.WriteLine("repository_denial_verified="+(denied?"1":"0"));
  }catch(Failure failure){Diagnostic(failure.stage,failure.code);}catch{Diagnostic(stage,0);}
  finally {if(impersonated&&!RevertToSelf()){Diagnostic("revert_identity",Marshal.GetLastWin32Error());Environment.Exit(96);}if(token!=IntPtr.Zero)CloseHandle(token);}
  return 0;
 }
 static int AccessDiagnostic(string[] args) {
  IntPtr token=IntPtr.Zero;bool impersonated=false;string stage="credential_logon";
  try {
   if(args.Length==7&&args[0]=="environment-access")return EnvironmentAccess(args);
   string password=Console.ReadLine();bool logged=LogonUser(args[1],Environment.MachineName,password,2,0,out token);
   password=null;Require(logged,stage);Console.WriteLine("credential_logon=1");
   stage="root_identity";using(WindowsIdentity id=new WindowsIdentity(token)){if(!Identity(id,args[2]))throw new Failure(stage,0);}
   Console.WriteLine("root_identity=1");stage="impersonate";Require(ImpersonateLoggedOnUser(token),stage);impersonated=true;
   // Actual restricted-token opens, not ACL string interpretation. No execute,
   // file creation, desktop changes, profile loading or permissions granted.
   for(int i=3;i<args.Length;i++) {
    bool directory=i==args.Length-1;
    IntPtr handle=CreateFile(args[i],directory?0x80000000u:0xA0000000u,7,IntPtr.Zero,3,directory?0x02000000u:0,IntPtr.Zero);
    int code=handle==new IntPtr(-1)?Marshal.GetLastWin32Error():0;
    if(code==0)CloseHandle(handle);
    Console.WriteLine("access="+(i-3)+","+code);
   }
  } catch(Failure failure){Diagnostic(failure.stage,failure.code);}catch{Diagnostic(stage,0);}
  finally {
   if(impersonated&&!RevertToSelf()){Diagnostic("revert_identity",Marshal.GetLastWin32Error());Environment.Exit(96);}
   if(token!=IntPtr.Zero&&!CloseHandle(token))Diagnostic("close_token",Marshal.GetLastWin32Error());
  }
  return 0;
 }
 static int Main(string[] args) {
  try {
   if(args.Length>=5&&args.Length<=12&&args[0]=="access")return AccessDiagnostic(args);
   if(args.Length==9&&args[0]=="chromium")return ChromiumLaunch(args);
   if(args.Length>=5&&args.Length<=12&&args[0]=="launch") return Launch(args);
   if(args.Length>=3&&args.Length<=10&&args[0]=="probe") {
    string[] specs=new string[args.Length-2];Array.Copy(args,2,specs,0,specs.Length);return Probe(args[1],specs);
   }
   if(args.Length==3&&args[0]=="child") return Self(args[1])?64+Attempt(args[2]):97;
   if(args.Length==2&&args[0]=="control") {
    using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) Console.WriteLine("control_sid="+identity.User.Value);
    return Attempt(args[1]);
   }
  } catch {Diagnostic("main",0);return 96;}
  return 95;
 }
}
