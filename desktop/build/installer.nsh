; SiteLens 桌面版安装器定制（electron-builder nsis.include 挂载）。
;
; 三件事（desktop/TODO.md 安装器 DIY 落地）：
;   1) 默认装 D:\Program Files\SiteLens（有固定 D 盘时）——
;      C 盘安装是大忌（用户明确反馈），目录页仍可改；
;   2) 安装后把引擎目录追加进用户 PATH（HKCU\Environment），
;      终端可直接 `sitelens -config .sitelens.yml scan ...`；卸载时移除；
;   3) 卸载时询问是否保留扫描历史与偏好（默认保留，与
;      deleteAppDataOnUninstall:false 的语义一致，只是给用户选择权）。
; 另：安装进度条填充色改品牌绿（#22c55e）。
;
; 说明：electron-builder 的 MUI2 向导模板不支持注入 nsDialogs 自绘页，
; 「添加到 PATH」做不了勾选项，改为默认开启（卸载自动移除，无残留）。
; StrFunc 声明按编译期分 pass 守卫：electron-builder 会用 /DBUILD_UNINSTALLER
; 把同一份脚本再编一遍（此时安装 Section 整体跳过），安装侧函数若照样声明
; 就会因「未引用」警告（warning 6010 = error）炸掉卸载器编译。
!include "StrFunc.nsh"
!ifndef BUILD_UNINSTALLER
${StrStr}
!else
${UnStrRep}
!endif

; 本文件在 MUI2/multiUser.nsh 之前被 include，而底部 Function 体在这里编译，
; ${INSTALL_REGISTRY_KEY} 当时还不存在——照模板的 /ifndef 原样提前定义
;（APP_GUID 是命令行 define，值与模板一致，模板侧 /ifndef 会跳过）。
!define /ifndef INSTALL_REGISTRY_KEY "Software\${APP_GUID}"

; _SL_BroadcastEnv 通知系统环境变量已变更（新开终端立即可见，免注销）。
!macro _SL_BroadcastEnv
  System::Call 'User32::SendMessageTimeout(i 0xffff, i 0x1A, i 0, t "Environment", i 2, i 1000, *i .r0) i.r0'
!macroend

!macro customInit
  ; 默认目录切到 D:\Program Files\SiteLens，仅当同时满足：
  ;   1) 无既往安装（注册表 InstallLocation 为空——升级装回原目录，不挪窝）；
  ;   2) 命令行未用 /D= 指定目录（用户显式指定优先）；
  ;   3) D: 是固定磁盘（GetDriveType=3）。
  ; 注意：customInit 在 initMultiUser 之后执行，此时 $INSTDIR 已被模板填成
  ; %LOCALAPPDATA%\Programs\SiteLens，不能拿「$INSTDIR 为空」当判断条件。
  ;
  ; 交互安装还有一层：模式选择页（仅为我/所有人）点下一步时
  ; setInstallModePerUser 会再读一次注册表并把 $INSTDIR 重置（无既往安装
  ; 时回落 C 盘用户目录），把这里直设的 D 盘覆盖掉——这正是「向导默认
  ; C 盘」的根因。所以交互模式下把默认值预写进 InstallLocation，让
  ; setInstallModePerUser 认领回来；安装完成时模板会用最终目录覆写该值，
  ; 中途取消由 .onUserAbort（SL_OnUserAbort）清除，不留假记录。
  ; 静默装没有页面链，$INSTDIR 直设即可，不写注册表。
  ReadRegStr $R0 HKCU "${INSTALL_REGISTRY_KEY}" "InstallLocation"
  ${If} $R0 == ""
    !insertmacro GetDParameter $R0
    ${If} $R0 == ""
      System::Call 'Kernel32::GetDriveType(t"D:\")i.r0'
      ${If} $0 == 3 ; DRIVE_FIXED
        StrCpy $INSTDIR "D:\Program Files\SiteLens"
        ${IfNot} ${Silent}
          WriteRegStr HKCU "${INSTALL_REGISTRY_KEY}" "InstallLocation" "$INSTDIR"
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

; 用户取消安装（确认弹窗后）：清掉预写的默认目录种子，避免下次被当成
; 「已有安装」。不动真实安装的记录：只有当值恰好是我们的默认目录、且
; 那里没有真实安装的卸载器时才删（无状态判断，卸载器 pass 编译也不炸）。
!define MUI_CUSTOMFUNCTION_ABORT SL_OnUserAbort
Function SL_OnUserAbort
  ReadRegStr $R0 HKCU "${INSTALL_REGISTRY_KEY}" "InstallLocation"
  StrCmp $R0 "D:\Program Files\SiteLens" 0 +3
  IfFileExists "$R0\Uninstall SiteLens.exe" +2 0
  DeleteRegValue HKCU "${INSTALL_REGISTRY_KEY}" "InstallLocation"
FunctionEnd

!macro customInstall
  ; 安装进度条填充色改品牌绿（PBM_SETBARCOLOR=0x0409，
  ; COLORREF 0x00BBGGRR：#22c55e → 0x005EC522）。找不到控件则无副作用。
  GetDlgItem $R8 $HWNDPARENT 1004
  ${If} $R8 <> 0
    SendMessage $R8 0x0409 0 0x005EC522
  ${EndIf}
  ; 用户 PATH 追加安装目录（幂等：已含则跳过；保证 CLI 可直接调引擎）
  ReadRegStr $R0 HKCU "Environment" "Path"
  ${StrStr} $R1 "$R0" "$INSTDIR"
  ${If} $R1 == ""
    ${If} $R0 == ""
      StrCpy $R2 "$INSTDIR"
    ${Else}
      StrCpy $R2 "$R0;$INSTDIR"
    ${EndIf}
    WriteRegExpandStr HKCU "Environment" "Path" "$R2"
    !insertmacro _SL_BroadcastEnv
    DetailPrint "已把 $INSTDIR 加入用户 PATH"
  ${EndIf}
!macroend

!macro customUnInstall
  ; 从用户 PATH 移除安装目录：分号边界三态（中/首/尾/唯一项）依次替换
  ReadRegStr $R0 HKCU "Environment" "Path"
  StrCpy $R1 "$INSTDIR"
  ${UnStrRep} $R2 "$R0" ";$R1" ""
  ${UnStrRep} $R2 "$R2" "$R1;" ""
  ${UnStrRep} $R2 "$R2" "$R1" ""
  ${If} $R2 != "$R0"
    WriteRegExpandStr HKCU "Environment" "Path" "$R2"
    !insertmacro _SL_BroadcastEnv
    DetailPrint "已从用户 PATH 移除 $INSTDIR"
  ${EndIf}
  ; 扫描历史与偏好的去留交给用户（%APPDATA%\SiteLens）。
  ; 静默模式（/S）不弹窗，默认保留——与 deleteAppDataOnUninstall:false 一致。
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION "是否保留扫描历史与偏好设置？$\n$\n选「否」将删除数据目录 %APPDATA%\SiteLens（含扫描历史、引擎日志与偏好）。" IDYES sl_keepdata
    RMDir /r "$APPDATA\SiteLens"
    DetailPrint "已删除扫描历史与偏好设置"
  sl_keepdata:
  ${EndIf}
!macroend
