"""
Memory Forensics Scanner - Process Hollowing Detection

Detects Process Hollowing via direct memory inspection using ctypes.
Reads PEB (Process Environment Block) and compares in-memory PE header
signature against expected "MZ" magic bytes.

Process Hollowing Technique:
1. Create blank process in suspended state
2. Unmaps legitimate image from memory
3. Maps malware image into same base address
4. Resumes thread - appears as legitimate process
5. PE header modified or missing in memory

Detection: Compare memory PE header vs expected signature
"""
import sys
import ctypes
from typing import Any
from typing import Dict
from basilisk.utils.logger import Logger


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """Windows Process Information Structure for NtQueryInformationProcess.
    
    PeBBaseAddress: Pointer to Process Environment Block (PEB) in user mode
    UniqueProcessId: Process ID
    Reserved fields: Kernel-level metadata
    """
    _fields_ = [
        ('Reserved1', ctypes.c_void_p),
        ('PebBaseAddress', ctypes.c_void_p),
        ('Reserved2', ctypes.c_void_p * 2),
        ('UniqueProcessId', ctypes.c_void_p),
        ('Reserved3', ctypes.c_void_p)
    ]


class MemoryScanner:
    """Detect process hollowing via PE header signature inspection.
    
    Windows-only capability using kernel32.dll and ntdll.dll for low-level
    process memory reading. Gracefully degrades to disabled on non-Windows.
    
    Core Functions:
    - NtQueryInformationProcess: Get PEB address (ntdll)
    - ReadProcessMemory: Read bytes from another process (kernel32)
    - PEB offset +0x10: Contains ImageBase address of loaded module
    
    Returns detection status with technique name for MITRE reporting.
    """

    def __init__(self):
        """Initialize memory scanner and load Windows API handles.
        
        Attempts to load kernel32 and ntdll DLLs. Gracefully disables
        on non-Windows platforms or if DLLs unavailable.
        """
        self.logger = Logger()
        self.is_windows = sys.platform == "win32"

        if self.is_windows:
            try:
                self.k32 = ctypes.windll.kernel32
                self.nt = ctypes.windll.ntdll

                self.PROCESS_VM_READ = 0x0010
                self.PROCESS_QUERY_INFORMATION = 0x0400
                self.PROCESS_VM_OPERATION = 0x0008

            except AttributeError:
                self.is_windows = False

    def _read_memory(self, process_handle, address, size):
        """Read bytes from another process via kernel32.ReadProcessMemory.
        
        Cross-process memory read with size validation. Returns None
        if read fails (access denied, invalid address, etc).
        
        Args:
            process_handle: Valid handle from OpenProcess (must have PROCESS_VM_READ)
            address: Target address in remote process
            size: Number of bytes to read
            
        Returns:
            bytes: Raw memory data or None if read failed
        """
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        success = self.k32.ReadProcessMemory(
            process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        return buffer.raw if success else None

    def detect_hollowing(self, pid: int) -> Dict[str, Any]:
        """Detect process hollowing by inspecting PE header signature.
        
        Process:
        1. Open process with QUERY_INFORMATION | VM_READ access
        2. Query NtQueryInformationProcess to get PEB address
        3. Read ImageBase from PEB+0x10 (module base address)
        4. Read first 512 bytes from ImageBase (PE header)
        5. Check for "MZ" magic bytes (0x4D5A)
        6. Missing/modified header indicates hollowing
        
        Args:
            pid: Process ID to inspect
            
        Returns:
            Dict[str, Any]: Detection result with fields:
                - suspicious: True if hollowing detected
                - technique: Description of finding (hollowing type or reason for non-detection)
        """
        if not self.is_windows:
            return {"suspicious": False, "technique": "N/A (Linux Env)"}

        process_handle = None
        try:
            process_handle = self.k32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
                False,
                pid
            )

            if not process_handle:
                return {"suspicious": False, "technique": "Access Denied"}

            pbi = PROCESS_BASIC_INFORMATION()
            return_len = ctypes.c_ulong()

            status = self.nt.NtQueryInformationProcess(
                process_handle,
                0,
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_len)
            )

            if status != 0:
                self.k32.CloseHandle(process_handle)
                return {"suspicious": False, "technique": "Query Failed"}

            peb_address = pbi.PebBaseAddress
            if not peb_address:
                self.k32.CloseHandle(process_handle)
                return {"suspicious": False, "technique": "No PEB"}

            image_base_buffer = self._read_memory(process_handle, peb_address + 0x10, 8)
            if not image_base_buffer:
                self.k32.CloseHandle(process_handle)
                return {"suspicious": False, "technique": "Read PEB Failed"}

            image_base = int.from_bytes(image_base_buffer, byteorder='little')

            header = self._read_memory(process_handle, image_base, 0x200)

            if header:
                if header[0:2] != b'MZ':
                    self.k32.CloseHandle(process_handle)
                    return {
                        "suspicious": True,
                        "technique": "Header Mismatch (No MZ)"
                    }

            self.k32.CloseHandle(process_handle)

            return {"suspicious": False, "technique": "None"}

        except Exception as e:
            if process_handle:
                self.k32.CloseHandle(process_handle)
            return {"suspicious": False, "technique": f"Error: {e}"}
