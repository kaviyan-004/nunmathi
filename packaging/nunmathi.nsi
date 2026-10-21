; NSIS installer for Nunmathi (Windows x64). Build from the repository root:
;   makensis -DVERSION=$(cat packaging/VERSION) packaging/nunmathi.nsi
; Expects the PyInstaller output in build\dist-win\nunmathi.
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !define VERSION "1.2.0"
!endif
!define APP "Nunmathi"
!define PUBLISHER "Nunmathi"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nunmathi"
!define SRC "..\build\dist-win\nunmathi"
!define GUI_EXE "Nunmathi.exe"
!define CLI_EXE "nunmathi-cli.exe"
!define WEBVIEW2_KEY "Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

Name "${APP} ${VERSION}"
OutFile "..\build\Nunmathi-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP}"
InstallDirRegKey HKLM "Software\${APP}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APP} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "${APP} IPsec VPN analyzer installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "${PUBLISHER}"

!define MUI_ICON "nunmathi.ico"
!define MUI_UNICON "nunmathi.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "Setup will install ${APP} ${VERSION}, a passive, AI-assisted IPsec VPN analyzer.$\r$\n$\r$\nNunmathi is a standalone desktop application: it opens in its own window and uses no browser and no network port. It needs the Microsoft Edge WebView2 Runtime, which Windows 10 and 11 already include.$\r$\n$\r$\nLive capture needs Wireshark (dumpcap) with Npcap; analysing pcap/pcapng files, the testbed and reports work without it."
!define MUI_FINISHPAGE_RUN "$INSTDIR\${GUI_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${APP} now"
!define MUI_FINISHPAGE_LINK "Get Wireshark + Npcap for live capture"
!define MUI_FINISHPAGE_LINK_LOCATION "https://www.wireshark.org/download.html"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APP} requires 64-bit Windows 10 or later."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "!${APP} (required)" SecMain
  SectionIn RO
  ; remove files of a previous version first, so stale modules never mix with new ones
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\${GUI_EXE}"
  ; the product was called VeilScope up to 1.1.0: remove that installation silently (its user data is kept and
  ; moved to %LOCALAPPDATA%\Nunmathi on first start)
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VeilScope" "InstallLocation"
  StrCmp $0 "" +3
  IfFileExists "$0\Uninstall.exe" 0 +2
  ExecWait '"$0\Uninstall.exe" /S _?=$0'
  StrCmp $0 "" +2
  RMDir /r "$0"
  SetOutPath "$INSTDIR"
  File /r "${SRC}\*.*"
  File "nunmathi.ico"
  File /oname=README.md "..\README.md"

  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\nunmathi.ico" 0 SW_SHOWNORMAL "" "IPsec VPN analyzer"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP} command line.lnk" "$SYSDIR\cmd.exe" '/k "cd /d "$DOCUMENTS" && set "PATH=$INSTDIR;%PATH%" && nunmathi-cli --help"' "$INSTDIR\nunmathi.ico" 0
  CreateShortcut "$SMPROGRAMS\${APP}\README.lnk" "$INSTDIR\README.md"
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk" "$INSTDIR\Uninstall.exe"

  WriteRegStr HKLM "Software\${APP}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${GUI_EXE}" "" "$INSTDIR\${GUI_EXE}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${CLI_EXE}" "" "$INSTDIR\${CLI_EXE}"
  ; "Open with > Nunmathi" for captures, without taking the default association away from Wireshark
  WriteRegStr HKLM "Software\Classes\Applications\${GUI_EXE}\shell\open\command" "" '"$INSTDIR\${GUI_EXE}" "%1"'
  WriteRegStr HKLM "Software\Classes\Applications\${GUI_EXE}" "FriendlyAppName" "${APP}"
  WriteRegStr HKLM "Software\Classes\Applications\${GUI_EXE}\SupportedTypes" ".pcap" ""
  WriteRegStr HKLM "Software\Classes\Applications\${GUI_EXE}\SupportedTypes" ".pcapng" ""
  WriteRegStr HKLM "Software\Classes\Applications\${GUI_EXE}\SupportedTypes" ".cap" ""
  WriteRegStr HKLM "Software\Classes\.pcap\OpenWithList\${GUI_EXE}" "" ""
  WriteRegStr HKLM "Software\Classes\.pcapng\OpenWithList\${GUI_EXE}" "" ""
  WriteRegStr HKLM "Software\Classes\.cap\OpenWithList\${GUI_EXE}" "" ""
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\nunmathi.ico"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"
  Call CheckWebView2
SectionEnd

Function CheckWebView2
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\${WEBVIEW2_KEY}" "pv"
  StrCmp $0 "" 0 +2
  ReadRegStr $0 HKLM "SOFTWARE\${WEBVIEW2_KEY}" "pv"
  StrCmp $0 "" 0 +2
  ReadRegStr $0 HKCU "Software\${WEBVIEW2_KEY}" "pv"
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "${APP} needs the Microsoft Edge WebView2 Runtime, which is not installed on this computer.$\r$\n$\r$\nOpen Microsoft's download page now? (Install the 'Evergreen Bootstrapper', then start ${APP}.)" /SD IDNO IDNO +2
      ExecShell "open" "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
  ${EndIf}
FunctionEnd

Section "Desktop shortcut" SecDesktop
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\nunmathi.ico" 0 SW_SHOWNORMAL
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Program files, Start-menu shortcuts and uninstaller."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Put a Nunmathi shortcut on the desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  ; stop a running instance so its files can be removed
  nsExec::Exec 'taskkill /F /IM ${GUI_EXE}'
  nsExec::Exec 'taskkill /F /IM ${CLI_EXE}'
  Delete "$DESKTOP\${APP}.lnk"
  RMDir /r "$SMPROGRAMS\${APP}"
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\${GUI_EXE}"
  Delete "$INSTDIR\${CLI_EXE}"
  Delete "$INSTDIR\nunmathi.ico"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${GUI_EXE}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${CLI_EXE}"
  DeleteRegKey HKLM "Software\Classes\Applications\${GUI_EXE}"
  DeleteRegKey HKLM "Software\Classes\.pcap\OpenWithList\${GUI_EXE}"
  DeleteRegKey HKLM "Software\Classes\.pcapng\OpenWithList\${GUI_EXE}"
  DeleteRegKey HKLM "Software\Classes\.cap\OpenWithList\${GUI_EXE}"
  DeleteRegKey HKLM "Software\${APP}"
  MessageBox MB_YESNO|MB_ICONQUESTION "Also delete your Nunmathi data (captures, analyses and model cache in $LOCALAPPDATA\Nunmathi)?" /SD IDNO IDNO keep
    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\Nunmathi"
  keep:
SectionEnd
