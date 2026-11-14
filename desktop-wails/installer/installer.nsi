; SiteLens 站点透视 — Windows 安装器 (NSIS)
; CI 构建: makensis -V2 -DVERSION=1.0.0 -DSTAGEDIR=SiteLens -DOUTFILE=dist/SiteLens-1.0.0-setup.exe installer/installer.nsi
; 注意: 本文件必须保存为 UTF-8 with BOM（makensis 中文脚本要求）

!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!ifndef STAGEDIR
  !define STAGEDIR "SiteLens"
!endif
!ifndef OUTFILE
  !define OUTFILE "SiteLens-setup.exe"
!endif
; 编译期源根目录（notice/staging 所在仓库根）：调用方传 -DSRCDIR=$PWD，
; 缺省按 makensis3 相对脚本目录语义回退到上一级
!ifndef SRCDIR
  !define SRCDIR ".."
!endif

Unicode true
ManifestDPIAware true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "SiteLens 站点透视 ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\SiteLens"
InstallDirRegKey HKLM "Software\SiteLens" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUnInstDetails show

; 升级目录解析：优先 Software\SiteLens\InstallDir（InstallDirRegKey 已处理）；
; 旧版本没有该键时回退卸载表 UninstallString 的父目录，避免静默安装默认落到
; C:\Program Files 与旧目录形成双安装（2026-11-01 真机回归发现）。
;
; 5.3.3 修复：NSIS 引导程序是 32 位，默认读 HKLM\Software 会被 WOW64 重定向到
; WOW6432Node；本产品把安装目录写在 64 位视图（Section 内 SetRegView 64），
; 不先切视图就读不到 → 静默升级会落到默认 C:\Program Files，与旧目录（如
; D:\Program Files\SiteLens）形成双安装。这里先切 64 位视图，读不到再回退 32 位。
Function .onInit
  SetRegView 64
  ReadRegStr $0 HKLM "Software\SiteLens" "InstallDir"
  ${If} $0 == ""
    ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "UninstallString"
    ${If} $0 != ""
      ${GetParent} "$0" $0
    ${EndIf}
  ${EndIf}
  ${If} $0 == ""
    SetRegView 32
    ReadRegStr $0 HKLM "Software\SiteLens" "InstallDir"
    ${If} $0 == ""
      ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "UninstallString"
      ${If} $0 != ""
        ${GetParent} "$0" $0
      ${EndIf}
    ${EndIf}
    SetRegView 64
  ${EndIf}
  ${If} $0 != ""
    StrCpy $INSTDIR "$0"
  ${EndIf}
FunctionEnd

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "SiteLens 站点透视 安装向导"
!define MUI_FINISHPAGE_RUN "$INSTDIR\sitelens.exe"
!define MUI_FINISHPAGE_RUN_TEXT "安装完成后立即启动 SiteLens"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SRCDIR}/installer/notice.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=2052 "ProductName" "SiteLens 站点透视"
VIAddVersionKey /LANG=2052 "FileDescription" "SiteLens 站点透视安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "fengqiao"

Section "SiteLens 站点透视" SEC_MAIN
  ; 静默覆盖更新（/S）前先结束正在运行的旧进程并等待文件解锁：
  ; 旧壳被 app.Quit 关闭需要时间，直接 File 覆盖会因 sitelens.exe 被占用而失败，
  ; 表现为“安装器跑了但版本没变”。taskkill 是兜底（正常退出路径不会命中）。
  ${If} ${Silent}
    ExecWait '"$SYSDIR\taskkill.exe" /IM sitelens.exe /F /T'
    ExecWait '"$SYSDIR\taskkill.exe" /IM sitelens-engine.exe /F /T'
    Sleep 1200
  ${EndIf}
  SetOutPath "$INSTDIR"
  ; Windows 版 makensis 的 File 不认正斜杠路径段（实测 `C:\stage/SiteLens/*.*`
  ; 会退化成 `File: Returning to: "C:"` + “no files found”），必须反斜杠。
  File /r "${SRCDIR}\${STAGEDIR}\*.*"

  ; 静默覆盖更新（/S，桌面壳自动更新拉起时）没有完成页——MUI_FINISHPAGE_RUN
  ; 只作用于交互向导的完成页；静默路径的新版启动统一放在本 Section 末尾
  ; （所有文件/注册表落盘之后），避免新进程读到半写文件。
  ;
  ; 注意（如实说明，不粉饰）：本安装器是**机器级**安装（RequestExecutionLevel
  ; admin + $PROGRAMFILES64），因此从非提权进程拉起的自动更新会弹一次 UAC。
  ; 这不影响「就地覆盖、无向导页、装完自动重开」的语义，但不是零交互升级；
  ; 要做到零 UAC 需改用户级安装（per-user + $LOCALAPPDATA），那是安装形态的
  ; 变更，另行评估。

  ; 开始菜单快捷方式
  CreateDirectory "$SMPROGRAMS\SiteLens"
  CreateShortcut "$SMPROGRAMS\SiteLens\SiteLens 站点透视.lnk" "$INSTDIR\sitelens.exe"
  CreateShortcut "$SMPROGRAMS\SiteLens\卸载 SiteLens.lnk" "$INSTDIR\uninstall.exe"

  ; 桌面快捷方式
  CreateShortcut "$DESKTOP\SiteLens 站点透视.lnk" "$INSTDIR\sitelens.exe"

  ; 卸载器与注册表登记（控制面板"程序和功能"可见）
  ; 64 位系统上切到 x64 注册表视图，避免 32 位安装器被 WOW64 重定向到 WOW6432Node
  SetRegView 64
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\SiteLens" "InstallDir" $INSTDIR
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "DisplayName" "SiteLens 站点透视 ${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "DisplayIcon" "$INSTDIR\sitelens.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "Publisher" "fengqiao"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "NoRepair" 1

  ; 静默更新：所有文件/注册表落盘后再拉起新版（避免新进程读到半写文件）。
  ${If} ${Silent}
    Exec "$INSTDIR\sitelens.exe"
  ${EndIf}

  DetailPrint "安装完成：$INSTDIR"
SectionEnd

Section "Uninstall"
  RMDir /r "$INSTDIR"
  RMDir /r "$SMPROGRAMS\SiteLens"
  Delete "$DESKTOP\SiteLens 站点透视.lnk"
  SetRegView 64
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens"
  DeleteRegKey HKLM "Software\SiteLens"
  DetailPrint "SiteLens 已卸载"
SectionEnd
