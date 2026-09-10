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

Name "SiteLens 站点透视 ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\SiteLens"
InstallDirRegKey HKLM "Software\SiteLens" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUnInstDetails show

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
  SetOutPath "$INSTDIR"
  File /r "${SRCDIR}/${STAGEDIR}/*.*"

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
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "Publisher" "fengqiao"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SiteLens" "NoRepair" 1

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
