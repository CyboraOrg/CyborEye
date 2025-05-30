import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def disassemble_pe(filepath, max_instructions=50):
    try:
        binary = lief.parse(filepath)
        entrypoint = binary.optional_header.addressof_entrypoint
        imagebase = binary.optional_header.imagebase
        code_section = next((s for s in binary.sections if "text" in s.name.lower()), None)

        if not code_section:
            return {"error": "No .text section found in binary."}

        code = bytes(code_section.content)
        code_offset = code_section.virtual_address

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        instructions = []
        for i, insn in enumerate(md.disasm(code, imagebase + code_offset)):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str
            })
            if i >= max_instructions:
                break

        return {
            "entrypoint": hex(imagebase + entrypoint),
            "disassembly_preview": instructions
        }
    except Exception as e:
        return {"error": f"Failed to disassemble file: {str(e)}"}