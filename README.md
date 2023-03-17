# Luau Disassembler in Luau

## Usage
```lua
local disassemble = require("luau-disassambler")
local disassembly = disassemble(bytecode, {
	showBytecodeOffsets = false,
	showRawBytes = false,
	useRobloxOpcodes = true,
})
```