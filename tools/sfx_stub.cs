// 构建命令（Windows 自带 .NET 4 编译器，无第三方依赖）：
//   csc -nologo -optimize -r:System.IO.Compression.FileSystem.dll -r:System.IO.Compression.dll -out:stub.exe tools\sfx_stub.cs
//   python 拼接: stub + zip + struct.pack('<Q', len(zip)) -> SiteLens-Setup.exe
// SiteLens 自解压安装器存根（.NET Framework 4 自带 csc 编译，无第三方依赖）。
// 结构：[存根 exe][zip 原始字节][8 字节小端 zip 长度]
// 运行：定位自身尾部的 zip，解压到当前工作目录，保留包内相对路径。
using System;
using System.IO;
using System.IO.Compression;

class Sfx
{
    const long Trailer = 8; // 尾部长度字段字节数

    static int Main(string[] args)
    {
        try
        {
            var self = System.Reflection.Assembly.GetExecutingAssembly().Location;
            using (var fs = File.OpenRead(self))
            {
                if (fs.Length < Trailer + 4)
                    return Fail("安装包不完整");
                fs.Seek(-Trailer, SeekOrigin.End);
                var tb = new byte[Trailer];
                if (fs.Read(tb, 0, tb.Length) != tb.Length)
                    return Fail("读取长度失败");
                long zlen = BitConverter.ToInt64(tb, 0);
                long zstart = fs.Length - Trailer - zlen;
                if (zstart < 0)
                    return Fail("定位 zip 失败");

                fs.Seek(zstart, SeekOrigin.Begin);
                var zip = new byte[zlen];
                var read = 0;
                while (read < zlen)
                {
                    int n = fs.Read(zip, read, (int)zlen - read);
                    if (n <= 0) return Fail("读取 zip 失败");
                    read += n;
                }

                var cwd = Directory.GetCurrentDirectory();
                Console.WriteLine("SiteLens 安装器：解压到 " + cwd);
                using (var ms = new MemoryStream(zip))
                using (var za = new ZipArchive(ms, ZipArchiveMode.Read))
                {
                    int n = 0;
                    foreach (var e in za.Entries)
                    {
                        var target = Path.Combine(cwd, e.FullName);
                        var dir = Path.GetDirectoryName(target);
                        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                        if (e.FullName.EndsWith("/") || e.FullName.EndsWith("\\") || e.Name == "")
                            continue;
                        using (var es = e.Open())
                        using (var ts = File.Create(target))
                            es.CopyTo(ts);
                        n++;
                        if (n % 2000 == 0) Console.WriteLine("  已释放 " + n + " 个文件…");
                    }
                    Console.WriteLine("完成：共释放 " + n + " 个文件。");
                }
                Console.WriteLine("运行 sitelens.exe 即可启动（默认 http://127.0.0.1:5000）。");
                return 0;
            }
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    static int Fail(string msg)
    {
        Console.Error.WriteLine("SiteLens 安装器错误：" + msg);
        return 1;
    }
}
