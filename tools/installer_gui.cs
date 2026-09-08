// SiteLens 图形安装向导（WinForms，Windows 自带 .NET 4 csc 编译，零第三方依赖）。
//
// 构建链（见 tools/build_installer.py）：
//   1. csc 编译本文件 -> 存根 exe
//   2. 存根 + [zip 原始字节][8 字节小端 zip 长度] -> SiteLens-Setup.exe
//
// 运行：双击出向导（品牌页 -> 选目录 -> 进度 -> 完成）；带 --silent <目录>
// 参数时跳过 UI 直接解压（供自动化/脚本用）。
// 设计取舍：不自动拉起任何程序，完成页仅展示安装路径——安装器的职责
// 是释放文件，启动交给用户。
using System;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

static class Installer
{
    // 品牌令牌（与产品 UI 一致：浅底 #fafafa / 深板岩 #0f172a / 品牌点 #3b82f6）
    static readonly Color Ink = Color.FromArgb(0x0f, 0x17, 0x2a);
    static readonly Color Paper = Color.FromArgb(0xfa, 0xfa, 0xfa);
    static readonly Color Accent = Color.FromArgb(0x3b, 0x82, 0xf6);
    static readonly Color Muted = Color.FromArgb(0x62, 0x6b, 0x7a);

    const long Trailer = 8;
    static string installedDir = "";

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "--silent")
        {
            var r = ExtractAll(args[1], null);
            Console.WriteLine(r == null ? "OK" : "ERR " + r);
            return r == null ? 0 : 1;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new WizardForm());
        return 0;
    }

    // ---- 解压核心（UI 与静默共用）----

    static string OpenOwn(out ZipArchive za)
    {
        za = null;
        var self = System.Reflection.Assembly.GetExecutingAssembly().Location;
        using (var probe = File.OpenRead(self))
        {
            if (probe.Length < Trailer + 4) return "安装包不完整";
            probe.Seek(-Trailer, SeekOrigin.End);
            var tb = new byte[Trailer];
            if (probe.Read(tb, 0, tb.Length) != tb.Length) return "读取长度失败";
            long zlen = BitConverter.ToInt64(tb, 0);
            long zstart = probe.Length - Trailer - zlen;
            if (zstart < 0) return "定位数据失败";
            probe.Seek(zstart, SeekOrigin.Begin);
            var zip = new byte[zlen];
            int read = 0;
            while (read < zlen)
            {
                int n = probe.Read(zip, read, (int)zlen - read);
                if (n <= 0) return "读取数据失败";
                read += n;
            }
            var ms = new MemoryStream(zip);
            za = new ZipArchive(ms, ZipArchiveMode.Read);
        }
        return null;
    }

    // 全量解压；onFile(target, i) 每文件回调（UI 进度用）。
    static string ExtractAll(string destDir, Action<string, int> onFile)
    {
        ZipArchive za;
        var err = OpenOwn(out za);
        if (err != null) return err;
        using (za)
        {
            Directory.CreateDirectory(destDir);
            int i = 0;
            foreach (var e in za.Entries)
            {
                var target = Path.Combine(destDir, e.FullName);
                var dir = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                if (e.FullName.EndsWith("/") || e.FullName.EndsWith("\\") || e.Name == "") continue;
                using (var es = e.Open())
                using (var ts = File.Create(target))
                    es.CopyTo(ts);
                i++;
                if (onFile != null) onFile(target, i);
            }
        }
        return null;
    }

    // ---- 向导窗体 ----

    class WizardForm : Form
    {
        TextBox dirBox;
        ProgressBar bar;
        Label fileLabel;
        Button backBtn, nextBtn, cancelBtn;
        Panel body;
        int step = 0; // 0=选目录 1=安装 2=完成

        public WizardForm()
        {
            Text = "SiteLens 安装向导";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(560, 400);
            BackColor = Paper;

            // 品牌头带：深板岩底 + 品牌点 + 词标
            var head = new Panel { Dock = DockStyle.Top, Height = 76, BackColor = Ink };
            head.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                g.FillEllipse(new SolidBrush(Accent), 28, 30, 16, 16);
            };
            var brand = new Label { Text = "SiteLens", ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 15F, FontStyle.Bold),
                AutoSize = true, Location = new Point(56, 18), BackColor = Color.Transparent };
            var sub = new Label { Text = "站点透视 · 安装向导", ForeColor = Color.FromArgb(0x9a, 0xa7, 0xba),
                Font = new Font("Microsoft YaHei UI", 9F), AutoSize = true,
                Location = new Point(58, 48), BackColor = Color.Transparent };
            head.Controls.Add(brand); head.Controls.Add(sub);
            Controls.Add(head);

            body = new Panel { Location = new Point(24, 100), Size = new Size(512, 230), BackColor = Paper };
            Controls.Add(body);

            // 底部按钮区
            backBtn = MkBtn("上一步", new Point(264, 348), false);
            nextBtn = MkBtn("开始安装", new Point(356, 348), true);
            cancelBtn = MkBtn("取消", new Point(464, 348), false);
            backBtn.Click += (s, e) => { if (step == 1) ShowStep(0); };
            cancelBtn.Click += (s, e) => Close();
            nextBtn.Click += (s, e) => Next();
            Controls.Add(backBtn); Controls.Add(nextBtn); Controls.Add(cancelBtn);
            AcceptButton = nextBtn;

            ShowStep(0);
        }

        Button MkBtn(string text, Point loc, bool primary)
        {
            var b = new Button
            {
                Text = text, Location = loc, Size = new Size(100, 32),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Microsoft YaHei UI", 9F),
                BackColor = primary ? Ink : Paper,
                ForeColor = primary ? Color.White : Ink,
            };
            b.FlatAppearance.BorderColor = Color.FromArgb(0xd6, 0xda, 0xe0);
            return b;
        }

        void ClearBody() { body.Controls.Clear(); }

        Label MkLabel(string text, float size, FontStyle style, Point loc, Color? color = null)
        {
            return new Label { Text = text, Font = new Font("Microsoft YaHei UI", size, style),
                Location = loc, AutoSize = true, ForeColor = color ?? Ink };
        }

        void ShowStep(int s)
        {
            step = s;
            ClearBody();
            backBtn.Visible = s == 1;
            nextBtn.Visible = s != 1;
            cancelBtn.Visible = s != 2;
            if (s == 0)
            {
                body.Controls.Add(MkLabel("选择安装位置", 14F, FontStyle.Bold, new Point(0, 8)));
                body.Controls.Add(MkLabel("将释放完整运行环境（程序 + 情报库 + 模板库，约 90MB，11000+ 文件）。", 9F, FontStyle.Regular, new Point(0, 44)));
                dirBox = new TextBox { Location = new Point(0, 84), Size = new Size(412, 26),
                    Font = new Font("Microsoft YaHei UI", 9.5F) };
                dirBox.Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SiteLens");
                var browse = MkBtn("浏览…", new Point(424, 82), false);
                browse.Click += (a, b) =>
                {
                    using (var d = new FolderBrowserDialog())
                    {
                        d.SelectedPath = dirBox.Text;
                        if (d.ShowDialog(this) == DialogResult.OK) dirBox.Text = d.SelectedPath;
                    }
                };
                var note = MkLabel("安装后运行目录中的 sitelens.exe，浏览器打开 http://127.0.0.1:5000 使用。", 9F, FontStyle.Regular, new Point(0, 130), Muted);
                body.Controls.Add(dirBox);
                body.Controls.Add(browse);
                body.Controls.Add(note);
                nextBtn.Text = "开始安装";
            }
            else if (s == 1)
            {
                body.Controls.Add(MkLabel("正在安装…", 14F, FontStyle.Bold, new Point(0, 8)));
                bar = new ProgressBar { Location = new Point(0, 52), Size = new Size(512, 22) };
                fileLabel = MkLabel("准备中…", 9F, FontStyle.Regular, new Point(0, 88), Muted);
                body.Controls.Add(bar);
                body.Controls.Add(fileLabel);
                nextBtn.Text = "安装中…";
                Task.Run(new Action(DoInstall));
            }
            else
            {
                body.Controls.Add(MkLabel("安装完成", 14F, FontStyle.Bold, new Point(0, 8)));
                var done = MkLabel("SiteLens 已安装到：" + installedDir, 9F, FontStyle.Regular, new Point(0, 46));
                done.MaximumSize = new Size(512, 0);
                var tip = MkLabel("运行目录中的 sitelens.exe，浏览器打开 http://127.0.0.1:5000 使用。\n卸载方式：直接删除安装目录。", 9F, FontStyle.Regular, new Point(0, 92), Muted);
                body.Controls.Add(done);
                body.Controls.Add(tip);
                nextBtn.Text = "完成";
            }
        }

        void Next()
        {
            if (step == 0)
            {
                var dir = dirBox.Text.Trim();
                if (dir == "") { MessageBox.Show("请选择安装位置"); return; }
                try { Directory.CreateDirectory(dir); }
                catch (Exception ex) { MessageBox.Show("目录不可写：" + ex.Message); return; }
                ShowStep(1);
            }
            else if (step == 2)
            {
                Close();
            }
        }

        void DoInstall()
        {
            var dir = dirBox.Text.Trim();
            var err = ExtractAll(dir, (file, i) =>
            {
                var f = Path.GetFileName(file);
                try
                {
                    Invoke(new Action(() =>
                    {
                        bar.Value = Math.Min(100, i * 100 / 11360);
                        fileLabel.Text = f;
                    }));
                }
                catch { }
            });
            if (err != null)
            {
                Invoke(new Action(() =>
                {
                    MessageBox.Show("安装失败：" + err);
                    ShowStep(0);
                }));
                return;
            }
            installedDir = dir;
            Invoke(new Action(() => ShowStep(2)));
        }
    }
}
