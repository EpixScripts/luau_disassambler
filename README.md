# Luau Disassembler in Luau

## Usage
```lua
local disassemble = require("disassembler")
local disassembly = disassemble(bytecode, {
	showBytecodeOffsets = false,
	showRawBytes = false,
})
```