# basilisk/modules/memory_scanner.py
"""
Basilisk EDR - Memory Forensics Module
Implements raw memory reading via ctypes to detect Process Hollowing.
"""
import psutil
import os
import sys
import ctypes
from typing import Any
from ctypes import wintypes
from typing import Dict, Optional
from basilisk.utils.logger import Logger

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('Reserved1', ctypes.c_void_p),
        ('PebBaseAddress', ctypes.c_void_p),
        ('Reserved2', ctypes.c_void_p * 2),
        ('UniqueProcessId', ctypes.c_void_p),
        ('Reserved3', ctypes.c_void_p)
    ]

class MemoryScanner:
    def __init__(self):
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
        """Lee bytes de la memoria de otro proceso."""
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
        """
        Analiza si el proceso ha sido vaciado (Hollowed) comparando
        la cabecera PE en memoria con la esperada.
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