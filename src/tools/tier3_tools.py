import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from typing import Dict, Any

def parse_pe_file(filepath: str) -> Dict[str, Any]:
    """
    Parses a Portable Executable (PE) file to extract its metadata, sections, and imports.
    This is a core tool for deep static analysis.

    :param filepath: The path to the PE file.
    :return: A structured dictionary of the PE file's metadata.
    """
    print(f"[T3 Tool] Parsing PE file {filepath}...")
    try:
        binary = lief.parse(filepath)
        # Type check to ensure we have a PE file before accessing PE-specific attributes
        if not isinstance(binary, lief.PE.Binary):
            return {"error": f"The file at {filepath} is not a valid PE (Windows executable) file."}

        result = {
            "entrypoint": hex(binary.optional_header.addressof_entrypoint),
            "image_base": hex(binary.optional_header.imagebase),
            "machine": str(binary.header.machine),
            "subsystem": str(binary.optional_header.subsystem),
            "has_signatures": binary.has_signatures,
            "sections": [{"name": s.name, "entropy": s.entropy, "size": s.size} for s in binary.sections],
            "imports": [lib.name for lib in binary.imports],
        }
        return result
    except Exception as e:
        return {"error": f"LIEF failed to parse '{filepath}' as a valid file: {str(e)}"}


def disassemble_pe_file(filepath: str, instruction_count: int = 30) -> Dict[str, Any]:
    """
    Disassembles the first few instructions at the entry point of a PE file using Capstone.
    This is a core tool for reverse engineering.

    :param filepath: The path to the PE file.
    :param instruction_count: The number of instructions to disassemble.
    :return: A dictionary containing the entry point and a list of disassembled instructions.
    """
    print(f"[T3 Tool] Disassembling entry point of {filepath}...")
    try:
        binary = lief.parse(filepath)
        if not isinstance(binary, lief.PE.Binary):
            return {"error": f"The file at {filepath} is not a valid PE (Windows executable) file."}
        
        arch = binary.header.machine
        
        # FIX: Compare the raw integer value of the machine type for maximum compatibility.
        # These values are part of the PE standard and do not change.
        if arch.value == 0x014c:  # IMAGE_FILE_MACHINE_I386
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch.value == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            return {"error": f"Unsupported architecture for disassembly: {arch}"}

        entry_point = binary.optional_header.addressof_entrypoint
        bytes_to_fetch = instruction_count * 16
        code = bytes(binary.get_content_from_virtual_address(entry_point, bytes_to_fetch))

        if not code:
            return {"error": "Could not read code from the entry point address."}
            
        disassembly = []
        base_address = binary.optional_header.imagebase
        for instr in md.disasm(code, base_address + entry_point):
            disassembly.append(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            if len(disassembly) >= instruction_count:
                break

        return {
            "entrypoint": hex(base_address + entry_point),
            "disassembly_preview": disassembly
        }
    except Exception as e:
        return {"error": f"An unexpected error occurred during disassembly: {str(e)}"}