/*
xdmp

tool that can dump memory from multiple processes
but only preserves one copy of a region that has the same
code section but might have different data sections
(I don't care about different data sections)

The solution is made to decrease the size of all process dump
and find the same modules in memory

author:			  deresz / gmail.com
based on the work of Vlad-Ioan Topan (vtopan / gmail.com)

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef LIBMDMP_H
#define LIBMDMP_H

// C:
#include <tchar.h>
// Platform SDK:
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>

#include "undocwin.h"

#define HASHDUMP_VER "0.1"
// timestamp: 11/1/2010 23:13:08

#define MDMP_DEBUG                  1
#define MDMP_DYN_DEBUG              0

#if MDMP_DYN_DEBUG
#define DEBUGBREAK __debugbreak()
#else
#define DEBUGBREAK
#endif

// C:
#include <tchar.h>
// Platform SDK:
#pragma warning(disable:4005) // avoid "macro redefinition" warning in sal.h
#include <windows.h>
#pragma warning(default:4005)

//=== macros =================================================================//
#define ALIGN_ADDR(addr, alignment) (addr % alignment) ? (addr + alignment - (addr % alignment)) : (addr)

//=== constants ==============================================================//
//--- MDmp API ---------------------------------------------------------------//
#define MDMP_FLAG_DONT_FIX_IMAGES           0x00000001
#define MDMP_FLAG_FIX_IMPORTS               0x00000002
#define MDMP_FLAG_SORT_BY_ADDR              0x00000004

#define MDMP_OK                             0x00000000
#define MDMP_ERR_MEM_ALLOC_FAILED           0x00010000
#define MDMP_ERR_ACCESS_DENIED              0x00010001
#define MDMP_ERR_PROC_SNAPSHOT_FAILED       0x00010003
#define MDMP_ERR_NO_PROCESS_MATCHES         0x00010004
#define MDMP_ERR_READ_MEM_FAILED            0x00010005
#define MDMP_ERR_INVALID_ARGS               0x00020000
#define MDMP_ERR_WRITING_TO_DISK            0x00030000
#define MDMP_ERR_UNK_ERROR                  0x000FFFFF

#define MDMP_WARN_OPEN_PROCESS_FAILED       0x00000001
#define MDMP_WARN_QUERY_INFO_FAILED         0x00000002
#define MDMP_WARN_MEM_ALLOC_FAILED          0x00000004
#define MDMP_WARN_READ_MEM_FAILED           0x00000008

#define MDMP_WARN_GET_MODULE_INFO_FAILED    0x01000000
#define MDMP_WARN_GET_PROCESS_INFO_FAILED   0x02000000
#define MDMP_WARN_ENUM_MODULES_FAILED       0x04000000
#define MDMP_WARN_ENUM_HEAPS_FAILED         0x08000000
#define MDMP_WARN_ENUM_THREADS_FAILED       0x10000000
#define MDMP_WARN_PAGE_GUARD_NOT_DUMPING    0x20000000

#define MDMP_DUMP_REGION                    0x00000001
#define MDMP_DUMP_MAIN_IMAGE                0x00000002
#define MDMP_DUMP_ALL_IMAGES                0x00000003
#define MDMP_DUMP_IMAGE_BY_IMAGEBASE        0x00000004
#define MDMP_DUMP_IMAGE_BY_NAME             0x00000005
#define MDMP_DUMP_STACKS                    0x00000006
#define MDMP_DUMP_HEAPS                     0x00000007
#define MDMP_DUMP_SMART                     0x00000008
#define MDMP_DUMP_EXECUTABLE                0x00000009
#define MDMP_DUMP_ALL_MEM                   0x0000000A

#define MDMP_SEL_BY_NAME                    0x00000001
#define MDMP_SEL_BY_PID                     0x00000002
#define MDMP_SEL_ALL                        0x00000003

#define MDMP_RT_IMAGE                       0x00000001
#define MDMP_RT_UNKNOWN                     0x000000FF

//--- other ------------------------------------------------------------------//
#define MAX_PROCESSES                       256
#define MD5LEN								16
#define MYMAX_PATH							256
#define FBUFSIZE							4096
#define MAX_MSG								256

//=== data types =============================================================//
//--- API --------------------------------------------------------------------//

struct MDMP_HASH {
	char hash[MD5LEN*2 + 1];
	TCHAR path[MYMAX_PATH];
	MDMP_HASH *next;
};

struct MDMP_DUMP_REQUEST {
   DWORD dumpMode, procSelMode;
   size_t imageBase, startAddr, endAddr;
   DWORD pid;
   DWORD flags;
   TCHAR processName[32], moduleName[32];
   struct MDMP_REGION *regionList;
   DWORD warnings;
   // callback?
   };

//=== APIs ===================================================================//
int __stdcall initMDmp(); // libMDmp initialization function; returns 1 on success, 0 on fail

DWORD __stdcall getDumps(struct MDMP_DUMP_REQUEST *req);

//TCHAR __stdcall processName(DWORD pid);

#endif // LIBMDMP_H
