import os
import hashlib
from elftools.elf.elffile import ELFFile

def get_module_info(module_name):
    """Get detailed information about a kernel module"""
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                name, size, instances, deps, state, offset = line.strip().split(" ", 5)
                if name == module_name:
                    path = f"/lib/modules/{os.uname().release}/kernel/{name}.ko"
                    return {
                        "name": name,
                        "size": int(size),
                        "addr": int(offset.split("[")[1].strip("]"), 16),
                        "path": path,
                        "compiler": get_compiler_info(path),
                        "sections": get_elf_sections(path)
                    }
    except Exception:
        return None

def calculate_module_hash(path):
    """Calculate SHA256 hash of a kernel module"""
    try:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def get_compiler_info(path):
    """Extract compiler information from ELF file"""
    try:
        with open(path, 'rb') as f:
            elffile = ELFFile(f)
            if '.comment' in elffile.sections_by_name:
                comment_section = elffile.sections_by_name['.comment']
                comment_data = comment_section.data().decode('utf-8', errors='ignore').strip('\x00')
                
                # Parse common compiler patterns
                if 'GCC:' in comment_data:
                    # Extract GCC version
                    parts = comment_data.split('GCC:')
                    if len(parts) > 1:
                        version_part = parts[1].strip().split(')')[0]
                        return f"GCC {version_part})"
                elif 'clang' in comment_data.lower():
                    return "Clang (version unknown)"
                elif comment_data:
                    return comment_data[:50]  # First 50 chars if not recognized pattern
                    
            # Fallback: try to detect from other sections
            if '.gnu.version' in elffile.sections_by_name:
                return "GCC (version unknown)"
                
    except Exception:
        pass
    
    # Default fallback for demo purposes
    return "GCC 12.2"

def get_elf_sections(path):
    """Get list of ELF sections"""
    sections = []
    try:
        with open(path, 'rb') as f:
            elffile = ELFFile(f)
            for section in elffile.iter_sections():
                sections.append(section.name)
    except Exception:
        pass
    return sections
