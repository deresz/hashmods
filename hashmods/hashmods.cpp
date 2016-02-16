// hashmods.cpp : Defines the entry point for the console application.
//
/*

hashmods

Tool that walks through process list, looks at all the modules,
and takes the hash of their on-disk version.

Something to complement autoruns from sysinternals.

author:			  deresz / gmail.com
based on the work of Vlad Ioan Topan (MDmp)
License: GNU GPL v3

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

//=== include ================================================================//
// local:
#include "stdafx.h"
#include "hashmods.h"

// C/C++:
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>
#include <stdint.h>

#include <stdio.h>

//===  globals ===============================================================//
typedef int(__cdecl *sprintf_template)(char *, const char *, ...);
typedef int(__cdecl *swprintf_template)(WCHAR *, const WCHAR *, ...);
sprintf_template ntdll_sprintf;
swprintf_template ntdll_swprintf;
HINSTANCE hNtDll;
SYSTEM_INFO systemInfo;

#ifdef UNICODE
#define _sprintf ntdll_swprintf
#else // UNICODE
#define _sprintf ntdll_sprintf
#endif // UNICODE

#define ALIGN_VALUE(x, alignment)	(((x) % (alignment) == 0) ? (x) : ((x) / (alignment) + 1) * (alignment))

DWORD(__stdcall * RtlAdjustPrivilege)(DWORD, DWORD, DWORD, PVOID);
DWORD(__stdcall * NtQueryInformationThread_)(HANDLE, THREAD_INFORMATION_CLASS1, PVOID, DWORD, PDWORD);
DWORD(__stdcall * NtQueryInformationProcess_)(HANDLE, PROCESS_INFORMATION_CLASS1, PVOID, DWORD, PDWORD);

TCHAR *UNKNOWN_TEXT = _T("[unknown]");
#define dumpMarkerSize 20
#define dumpMarkerPos 0x1E

#if _WIN64
# define IS64BIT
#else
# define IS32BIT
#endif

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

// macros to check if it's wow64

#ifdef IS64BIT

BOOL IsWow64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			// handle the error ?
		}
	}
	return bIsWow64;
}

#else

BOOL IsWow64(HANDLE hProcess)
{

	return FALSE;
}

#endif

HANDLE fhashes, fcsv, ferrors;
MDMP_HASH *hashlist;

void error(char *err) {
	
	DWORD written;
	fprintf(stderr, err);
	WriteFile(ferrors, err, strlen(err), &written, 0);
}


//=== memory functions ==========================================================================//

void *getMem(size_t size) {
	return LocalAlloc(0, size);
	//return VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

BOOL freeMem(void *ptr) {
	return LocalFree(ptr) == 0;
	//return VirtualFree(ptr, 0, MEM_RELEASE);
}

//=== auxiliary functions =======================================================================//

int adjustPrivileges() {
	// aquire SeDebugPrivilege (required for access to other processes' memory)
	DWORD prevState;

	//DEBUGBREAK;
	if (RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &prevState)) {
		return 0;
	}
	return 1;
}

int _startsWith(const TCHAR *s1, const TCHAR *s2) {
	// checks if s1 starts with s2
	int i = 0;
	while (1) {
		if (!s2[i]) {
			return 1;
		}
		if (s1[i] != s2[i]) {
			return 0;
		}
		i++;
	}
	return 0; // should never be reached; keeps compiler from complaining
}

void _lower(TCHAR *dest, const TCHAR *src, DWORD maxSize) {
	// put lowercase version of src in dest (dst must be preallocated of at least same size as src)
	DWORD i = 0;
	while (src[i] && (i < maxSize)) {
		dest[i] = ((TCHAR('A') <= src[i]) && (TCHAR('Z') >= src[i])) ? (src[i] - TCHAR('A') + TCHAR('a')) : src[i];
		i++;
	}
	if (i == maxSize) {
		i--;
	}
	dest[i] = 0;
}

int _length(const TCHAR *string) {
	// counts TCHARs in string up to and including the final \0
	int i = 0;
	while (string[i]) {
		i++;
	}
	return i + 1;
}

int _isSubString(const TCHAR *substring, const TCHAR *string) {
	//
	int i, result;
	TCHAR *substrLow, *strLow;
	if (!substring || !string) {
		return 0;
	}
	substrLow = (TCHAR *)getMem(sizeof(TCHAR)* _length(substring));
	if (!substrLow) {
		return 0;
	}
	strLow = (TCHAR *)getMem(sizeof(TCHAR)* _length(string));
	if (!strLow) {
		freeMem(substrLow);
		return 0;
	}
	_lower(substrLow, substring, 0xFFFFFFFF);
	_lower(strLow, string, 0xFFFFFFFF);
	result = 0;
	for (i = 0; 1; i++) {
		if (!strLow[i]) {
			break;
		}
		if (_startsWith(&strLow[i], substrLow)) {
			result = 1;
			break;
		}
	}
	freeMem(substrLow);
	freeMem(strLow);
	return result;
}

//=== crypto functions ==========================================================================//

DWORD initHash(HCRYPTPROV *hProv, HCRYPTHASH *hHash) {

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	*hProv = 0;
	*hHash = 0;

	if (!CryptAcquireContext(hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		return dwStatus;
	}

	if (!CryptCreateHash(*hProv, CALG_MD5, 0, 0, hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CryptReleaseContext(*hProv, 0);
		return dwStatus;
	}

	return 0;
}

DWORD updateHash(HCRYPTHASH hHash, HCRYPTPROV hProv, BYTE *rgbFile, size_t len) {
	DWORD dwStatus = 0;

	//printf("Updating hash: data at 0x%016x, size %x\n", rgbFile, len);
	if (!CryptHashData(hHash, rgbFile, len, 0))
	{
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return dwStatus;
	}
	return 0;
}

DWORD getHash(HCRYPTHASH hHash, char *hexHash) {

	DWORD cbHash;
	CHAR rgbDigits[] = "0123456789abcdef";
	BYTE rgbHash[MD5LEN];
	DWORD dwStatus;

	cbHash = MD5LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
		hexHash[0] = 0;
		return dwStatus;
	}

	//printf("cbhash: %d\n", cbHash);

	for (DWORD i = 0; i < cbHash; i++)
	{
		//printf("%c%c", rgbDigits[rgbHash[i] >> 4],
		//	rgbDigits[rgbHash[i] & 0xf]);
		sprintf(hexHash + 2 * i, "%c%c", rgbDigits[rgbHash[i] >> 4],
			rgbDigits[rgbHash[i] & 0xf]);
	}
	//printf("\n");

	hexHash[MD5LEN * 2] = 0;

	return 0;
}

void destroyHash(HCRYPTHASH hHash, HCRYPTPROV hProv)
{
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
}

void addHash(char *hash, TCHAR *path) {

	MDMP_HASH *newhash = (MDMP_HASH *)getMem(sizeof(MDMP_HASH));
	newhash->next = hashlist;
	strcpy(newhash->hash, hash);
	strcpy(newhash->path, path);
	hashlist = newhash;
}

char *findHashByPath(char *path) {
	MDMP_HASH *current = hashlist;
	while (current) {
		if (!strcmp(path, current->path)) {
			return current->hash;
		}
		current = current->next;
	}
	return NULL;
}

BOOL hashModule(TCHAR *path, char *hash) {
	HCRYPTPROV  hProv = NULL;
	HCRYPTHASH  hHash = NULL;
	initHash(&hProv, &hHash);

	BYTE tmpbuf[FBUFSIZE];
	HANDLE hModuleImage;
	BOOL readOk;
	DWORD bytesRead;

	LPTSTR errorText;
	
	char msg[MAX_MSG];

	hModuleImage = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hModuleImage == INVALID_HANDLE_VALUE) {

		FormatMessage(
			// use system message tables to retrieve error text
			FORMAT_MESSAGE_FROM_SYSTEM
			// allocate buffer on local heap for error text
			| FORMAT_MESSAGE_ALLOCATE_BUFFER
			// Important! will fail otherwise, since we're not 
			// (and CANNOT) pass insertion parameters
			| FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,  // output 
			0, // minimum size for output buffer
			NULL);   // arguments - see note 

		_sprintf(msg, "%s: cannot open file for reading: %s", path, errorText);
		error(msg);
		return FALSE;
	}
	readOk = ReadFile(hModuleImage, tmpbuf, FBUFSIZE, &bytesRead, NULL);
	if (!readOk) {

		FormatMessage(
			// use system message tables to retrieve error text
			FORMAT_MESSAGE_FROM_SYSTEM
			// allocate buffer on local heap for error text
			| FORMAT_MESSAGE_ALLOCATE_BUFFER
			// Important! will fail otherwise, since we're not 
			// (and CANNOT) pass insertion parameters
			| FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,  // output 
			0, // minimum size for output buffer
			NULL);   // arguments - see note 

		_sprintf(msg, "%s: error reading file: %s", path, errorText);
		error(msg);
		CloseHandle(hModuleImage);
		return FALSE;
	}
	while (bytesRead) {
		if (updateHash(hHash, hProv, tmpbuf, bytesRead)) {
			_sprintf(msg, _T("%s: hash update failed\n"), path);
			error(msg);
			CloseHandle(hModuleImage);
			return FALSE;
		}
		readOk = ReadFile(hModuleImage, tmpbuf, FBUFSIZE, &bytesRead, NULL);
		if (!readOk) {
			FormatMessage(
				// use system message tables to retrieve error text
				FORMAT_MESSAGE_FROM_SYSTEM
				// allocate buffer on local heap for error text
				| FORMAT_MESSAGE_ALLOCATE_BUFFER
				// Important! will fail otherwise, since we're not 
				// (and CANNOT) pass insertion parameters
				| FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
				GetLastError(),
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&errorText,  // output 
				0, // minimum size for output buffer
				NULL);   // arguments - see note 
			_sprintf(msg, "%s: error reading file: %s", path, errorText);
			error(msg);
			CloseHandle(hModuleImage);
			return FALSE;
		}
	}
	getHash(hHash, hash);
	CloseHandle(hModuleImage);
	return TRUE;

}

//=== CLI functions ==============================================================//

int getIntArg(char *arg) {
	int j = 0;

	while (arg[j] && (arg[j] == ':' || arg[j] == '=' || arg[j] == ' ')) {
		j++;
	}
	return atoi(&arg[j]);
}

char *getStrArg(char *arg) {
	int j = 0;

	while (arg[j] && (arg[j] == ':' || arg[j] == '=' || arg[j] == ' ')) {
		j++;
	}
	return &arg[j];
}


void displayHelp() 

{
		printf("hashmods %s: tool to collect all on-disk hashes of the loaded module in a process (or all processes)", HASHDUMP_VER);

		printf("\nProcess selection:\n\
			   /a          dump from all processes (default)\n\
			   /p:###      by PID (dump from process with PID = ### (decimal))\n\
			   /n:###      by name (dump from process with image name containing \"###\")\n\n\
			   Dump target selection:\n\
			   default:    main executable image(s)\n\
			   Options:\n\
			   /F          DON'T fix image dumps\n\
			   /I          fix imports\n\
			   Notes:\n\
			    - at least one of target or process selection required\n\
				 - \"/\" can be replaced with \"-\"\n\
				 ");
}

// === main loop function =========================================================================================

DWORD __stdcall getDumps(struct MDMP_DUMP_REQUEST *req) {
	// main workhorse; see help for details
	size_t i, j, count, npids, remotePEBAddr;
	SIZE_T readBytes;
	DWORD pids[MAX_PROCESSES], sizeD, written;
	DWORD pid;
	HMODULE *hModules;
	MODULEINFO modInfo;
	HANDLE snap, hProcess;
	TCHAR crtProcess[MYMAX_PATH],  msg[MAX_MSG];
	PROCESSENTRY32 pe32;
	PEB_UNDOC remotePEB;
	PROCESS_BASIC_INFORMATION_UNDOC procInfo;
	DWORD myOwnPid = GetCurrentProcessId();
	TCHAR moduleName[MYMAX_PATH];
	char *currHash;
	LPTSTR errorText;

	HCRYPTPROV  hProv = NULL;
	HCRYPTHASH  hHash = NULL;

	fcsv = CreateFile("hashmods.csv", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	fhashes = CreateFile("unique_hashes.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	ferrors = CreateFile("errors.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	_sprintf(msg, _T("Hash,PID,Base,Path\n"));
	WriteFile(fcsv, msg, strlen(msg), &written, 0);

	// select processes
	if (req->procSelMode == MDMP_SEL_BY_PID) { // single PID
		if (!req->pid) {
			return MDMP_ERR_INVALID_ARGS;
		}
		pids[0] = req->pid;
		npids = 1;
	}
	else { // enumerate processes to select PIDs
		if (req->procSelMode == MDMP_SEL_BY_NAME && ((!req->processName) || (!req->processName[0]))) {
			return MDMP_ERR_INVALID_ARGS;
		}
		npids = 0;
		snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) {
			return MDMP_ERR_PROC_SNAPSHOT_FAILED;
		}
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(snap, &pe32)) {
			CloseHandle(snap);
			return MDMP_ERR_PROC_SNAPSHOT_FAILED;
		}
		do {
			if ((req->procSelMode == MDMP_SEL_ALL) && (pe32.th32ProcessID != myOwnPid) || (req->procSelMode == MDMP_SEL_BY_NAME && _isSubString(req->processName, pe32.szExeFile))) {
				pids[npids++] = pe32.th32ProcessID;
			}
			if (npids == MAX_PROCESSES) {
				break;
			}
		} while (Process32Next(snap, &pe32));
		CloseHandle(snap);
	}

	if (!npids) {
		return MDMP_ERR_NO_PROCESS_MATCHES;
	}

	// walk selected processes
	for (i = 0; i < npids; i++) {
		//DEBUGBREAK;
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, 0, pids[i]);
		if (!hProcess) {
		
			FormatMessage(
				// use system message tables to retrieve error text
				FORMAT_MESSAGE_FROM_SYSTEM
				// allocate buffer on local heap for error text
				| FORMAT_MESSAGE_ALLOCATE_BUFFER
				// Important! will fail otherwise, since we're not 
				// (and CANNOT) pass insertion parameters
				| FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
				GetLastError(),
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&errorText,  // output 
				0, // minimum size for output buffer
				NULL);   // arguments - see note 


			req->warnings |= MDMP_WARN_OPEN_PROCESS_FAILED;
			_sprintf(msg, _T("pid %d: open process failed: %s"), pids[i], errorText);
			error(msg);
			continue;
		}

		if (IsWow64(hProcess))
			continue;
		pid = GetProcessId(hProcess);

		//hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pids[i]);

		if (!GetModuleBaseName(hProcess, 0, crtProcess, sizeof(crtProcess) / sizeof(crtProcess[0]))) {
			req->warnings |= MDMP_WARN_ENUM_MODULES_FAILED;
			continue;
		}

		printf("--> process %s(%d):\n", crtProcess, pid);

		// suspend process threads
		//toggleProcessState(pids[i], TRUE);

		// read remote PEB
		if (NtQueryInformationProcess_(hProcess, ProcessBasicInformation_, &procInfo, sizeof(procInfo), 0) < 0xC0000000) {
			remotePEBAddr = (size_t)procInfo.PebBaseAddress;
			ReadProcessMemory(hProcess, procInfo.PebBaseAddress, &remotePEB, sizeof(PEB_UNDOC), &readBytes);
		}
		else {
			remotePEBAddr = 0;
		}

		// get dump
		// dump image(s)
		EnumProcessModules(hProcess, 0, 0, &sizeD);
		if ((sizeD > 0) && (sizeD <= 8192)) {
			hModules = (HMODULE *)getMem(sizeD);
			if (hModules) {
				if (EnumProcessModules(hProcess, hModules, sizeD, &sizeD)) {
					count = sizeD / sizeof(HMODULE*);
					for (j = 0; j < count; j++) {	
						GetModuleInformation(hProcess, hModules[j], &modInfo, sizeof(modInfo));
						GetModuleFileNameEx(hProcess, hModules[j], moduleName, MYMAX_PATH - 1);	
						currHash = findHashByPath(moduleName);
						if (!currHash) {
							currHash = (char *)getMem(MD5LEN * 2 + 1);
							if (hashModule(moduleName, currHash)) {
								if (!currHash) {
									freeMem(currHash);
									currHash = "*ERROR*";
								}
								else {
									addHash(currHash, moduleName);
									_sprintf(msg, _T("%s\n"), currHash);
									WriteFile(fhashes, msg, strlen(msg), &written, 0);
								}

							}
							else {
								freeMem(currHash);
								currHash = "*ERROR*";
							}
						}
#ifdef IS64BIT			
						_sprintf(msg, _T("%s,%5d,0x%016llx,\"%s\"\n"), currHash, pid, modInfo.lpBaseOfDll, moduleName);
#else
						_sprintf(msg, _T("%s,%5d,%08x,\"%s\"\n"), currHash, pid, modInfo.lpBaseOfDll, moduleName);
#endif			
						WriteFile(fcsv, msg, strlen(msg), &written, 0);
						
					}

				}
				else {
					_sprintf(msg, _T("%s(%d): enum modules failed\n"), crtProcess, pid);
					error(msg);
					req->warnings |= MDMP_WARN_ENUM_MODULES_FAILED;
				}
				freeMem(hModules);
			}
			else {
				req->warnings |= MDMP_WARN_MEM_ALLOC_FAILED;
			}
		}

		CloseHandle(hProcess);
	}

	CloseHandle(fcsv);
	CloseHandle(fhashes);
	CloseHandle(ferrors);
	printf("Hashing finished.\n");
	return MDMP_OK;
}

//=== initialization function ============================================================================

int __stdcall initMDmp() {
	// libMDmp initialization function; must be called before any other API
	// returns 1 on success, 0 on fail
	hashlist = NULL;
	hNtDll = GetModuleHandle("ntdll.dll"); // always loaded
	if (!hNtDll) {
		return 0;
	}
	*(FARPROC *)&RtlAdjustPrivilege = GetProcAddress(hNtDll, "RtlAdjustPrivilege");
	*(FARPROC *)&NtQueryInformationThread_ = GetProcAddress(hNtDll, "NtQueryInformationThread");
	*(FARPROC *)&NtQueryInformationProcess_ = GetProcAddress(hNtDll, "NtQueryInformationProcess");
#ifdef UNICODE
	*(FARPROC *)&ntdll_swprintf = GetProcAddress(hNtDll, "swprintf");
	if (!ntdll_swprintf) {
		return 0;
	}
#else // UNICODE
	*(FARPROC *)&ntdll_sprintf = GetProcAddress(hNtDll, "sprintf");
	if (!ntdll_sprintf) {
		return 0;
	}
#endif // UNICODE

	GetSystemInfo(&systemInfo);

	if (!adjustPrivileges()) {
		return 0;
	}

	return 1;
}


// === main() ===========================================================================================

int main(int argc, char *argv[], char *envp[]) {
	int i;
	DWORD res;
	MDMP_DUMP_REQUEST req;

	if (!initMDmp()) {
		printf("Failed initializing hashmods - you need to have admin rights!");
		return 1;
	}

	ZeroMemory(&req, sizeof(req));
	req.procSelMode = MDMP_SEL_ALL;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' || argv[i][0] == '/') {
			switch (argv[i][1]) {
			case 'h':
				displayHelp();
				return 1;
				break;
			case 'p':
				req.pid = getIntArg(&argv[i][2]);
				req.procSelMode = MDMP_SEL_BY_PID;
				break;
			case 'a':
				req.procSelMode = MDMP_SEL_ALL;
				break;
			case 'n':
				strcpy((char *)req.processName, getStrArg(&argv[i][2]));
				req.procSelMode = MDMP_SEL_BY_NAME;
				break;
			case 'F':
				req.flags |= MDMP_FLAG_DONT_FIX_IMAGES;
				break;
			case 'I':
				req.flags |= MDMP_FLAG_FIX_IMPORTS;
				break;
			}
		}

	}

	res = getDumps(&req);
	if (res != MDMP_OK) {
		printf("hashmods failed with code [%d]!", res);
	}
	return 0;
}


