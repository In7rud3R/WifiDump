#ifndef WLAN_PROFILE_GET_PLAINTEXT_KEY
#define WLAN_PROFILE_GET_PLAINTEXT_KEY 4 // Dont have the latest platform SDK on this box
#endif

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "crypt32.lib")


#include <stdio.h>
#include <windows.h>
#include <wlanapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <shellapi.h>
#include <strsafe.h>

void MyError(LPTSTR lpszFunction){
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	//MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
	wprintf_s(L"%s", lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
}

BOOL IsElevated()
{
	DWORD dwSize = 0;
	HANDLE hToken = NULL;
	BOOL bReturn = FALSE;

	TOKEN_ELEVATION tokenInformation;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	if (GetTokenInformation(hToken, TokenElevation, &tokenInformation, sizeof(TOKEN_ELEVATION), &dwSize))
	{
		bReturn = (BOOL)tokenInformation.TokenIsElevated;
	}

	CloseHandle(hToken);
	return bReturn;
}

BOOL IsVistaOrHigher()
{
	OSVERSIONINFO osVersion; ZeroMemory(&osVersion, sizeof(OSVERSIONINFO));
	osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&osVersion))
		return FALSE;

	if (osVersion.dwMajorVersion >= 6)
		return TRUE;
	return FALSE;
}

int main(int argc, char *argv[])
{
	HANDLE hWlan = NULL;
	PWLAN_INTERFACE_INFO_LIST	wlanInterfaceList = NULL;
	PWLAN_PROFILE_INFO_LIST		wlanProfileList = NULL;
	PWLAN_INTERFACE_INFO		pIfInfo = NULL;


	DWORD dwError = 0;
	DWORD dwSupportedVersion = 0;
	DWORD dwClientVersion = (IsVistaOrHigher() ? 2 : 1);

	//variables for decrypting key
	BYTE toKey[1024]; // binary representation of the hex password
	DWORD cbBinary = sizeof(toKey), dwSkip;
	WCHAR outBuffer[1024];
	DWORD dwSize;
	int key_auth_wep = 0;
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;

	FILE * out = stdout;
	for (int i = 1; i < argc; i++){
		if (strcmp(argv[i], "-o") == 0){
			if ((++i) < argc){
				if (fopen_s(&out, argv[i], "w") != 0){
					fprintf(stderr, "Error: Failed to open output\n");
					return 1;
				}
				printf("Redirecting output to %s\n", argv[i]);
			}
			else{
				fprintf(stderr, "Error: Missing output filename\n");
				return 1;
			}
		}
	}

	if (!IsElevated())
		printf("[!] Running without administrative rights\n");

	try{
		if (dwError = WlanOpenHandle(dwClientVersion, NULL, &dwSupportedVersion, &hWlan) != ERROR_SUCCESS){
			MyError(L"WlanOpenHandle");
			throw("[x] ");
		}

		if (dwError = WlanEnumInterfaces(hWlan, NULL, &wlanInterfaceList) != ERROR_SUCCESS){
			MyError(L"WlanEnumInterfaces");
			throw("[x] Unable to enum wireless interfaces");
		}

		if (wlanInterfaceList->dwNumberOfItems == 0) // Almost missed this before posting
			throw("[x] No wireless adapters detected");

		LPWSTR profileXML;

		fwprintf(out, L"\nNetwork\t\t\t\t\tPassword\n\n");
		for (unsigned int iw = 0; iw < wlanInterfaceList->dwNumberOfItems; iw++){	//for each interface
			DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY, dwAccess = 0;
			pIfInfo = (WLAN_INTERFACE_INFO *)&wlanInterfaceList->InterfaceInfo[iw];

			if (dwError = WlanGetProfileList(hWlan, &pIfInfo->InterfaceGuid, NULL, &wlanProfileList) != ERROR_SUCCESS){
				MyError(L"WlanGetProfileList");
				fwprintf(stderr, L"Unable to get profile list for interface%s\n", pIfInfo->strInterfaceDescription);
				continue;
			}

			for (unsigned int i = 0; i < wlanProfileList->dwNumberOfItems; i++){	//for each profile

				fwprintf(out, L"%s", wlanProfileList->ProfileInfo[i].strProfileName);
				int j = 20 - wcslen(wlanProfileList->ProfileInfo[i].strProfileName);

				for (int k = 0; k < j; k++)
					fwprintf(out, L" ");

				if (IsElevated()){
					if (WlanGetProfile(hWlan, &pIfInfo->InterfaceGuid,
						wlanProfileList->ProfileInfo[i].strProfileName,
						NULL, &profileXML, &dwFlags, &dwAccess) == ERROR_SUCCESS)
					{
						// This is really half assed but I'm really hungover
						int key_protected = 0;	//key is not encrypted
						WCHAR *pszStr = wcstok(profileXML, L"<>");
						while (pszStr) {
							if (!wcscmp(pszStr, L"keyMaterial")) {
								pszStr = wcstok(NULL, L"<>");

								if (key_protected){
									//convert hex to binary
									CryptStringToBinary(pszStr, wcslen(pszStr), CRYPT_STRING_HEX_ANY,
										toKey, &cbBinary, &dwSkip, &dwFlags);
									//decrypt the key
									DataIn.cbData = cbBinary;
									DataIn.pbData = (BYTE *)toKey;
									if (CryptUnprotectData(&DataIn, 0, NULL, NULL, NULL, 0, &DataOut)) {

										if (key_auth_wep == 1){	//if we have a WEP key
											dwSize = sizeof(outBuffer);
											CryptBinaryToString(DataOut.pbData, DataOut.cbData, CRYPT_STRING_HEX,
												outBuffer, &dwSize);
											pszStr = outBuffer;
										}
										else{
											pszStr = (wchar_t*)DataOut.pbData;
										}
									}
								}
								fwprintf(out, L"\t\t\t%s\n", pszStr);
								break;
							}
							else if (!wcscmp(pszStr, L"protected")) {
								pszStr = wcstok(NULL, L"<>");	//value for <protected> - true/false
								key_protected = (!wcscmp(pszStr, L"true")) ? 1 : 0;
							}
							else if (!wcscmp(pszStr, L"authentication")) {
								pszStr = wcstok(NULL, L"<>");
								key_auth_wep = (wcsstr(pszStr, L"WPA")) ? 1 : 0;
							}
							else{
								pszStr = wcstok(NULL, L"<>");
							}
						}
						WlanFreeMemory(profileXML);
					}
				}
				else{
					printf("\t\t\tAccess Denied.\n");
				}
			}
			if (wlanProfileList)
				WlanFreeMemory(wlanProfileList);
		}
	}
	catch (char *szError){
		printf("%s (0x%X)\nQuitting...\n", szError);
	}

	if (wlanInterfaceList)
		WlanFreeMemory(wlanInterfaceList);
	if (hWlan)
		WlanCloseHandle(hWlan, NULL);

	return dwError;
}
