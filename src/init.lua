--!optimize 2
-- Luau bytecode disassembler, written in Luau
-- Created by Epix#3333 (https://github.com/EpixScripts)
local IS_ROBLOX_CLIENT = true

local vanillaOpcodes = {
	NOP = 0,
	BREAK = 1,
	LOADNIL = 2,
	LOADB = 3,
	LOADN = 4,
	LOADK = 5,
	MOVE = 6,
	GETGLOBAL = 7,
	SETGLOBAL = 8,
	GETUPVAL = 9,
	SETUPVAL = 10,
	CLOSEUPVALS = 11,
	GETIMPORT = 12,
	GETTABLE = 13,
	SETTABLE = 14,
	GETTABLEKS = 15,
	SETTABLEKS = 16,
	GETTABLEN = 17,
	SETTABLEN = 18,
	NEWCLOSURE = 19,
	NAMECALL = 20,
	CALL = 21,
	RETURN = 22,
	JUMP = 23,
	JUMPBACK = 24,
	JUMPIF = 25,
	JUMPIFNOT = 26,
	JUMPIFEQ = 27,
	JUMPIFLE = 28,
	JUMPIFLT = 29,
	JUMPIFNOTEQ = 30,
	JUMPIFNOTLE = 31,
	JUMPIFNOTLT = 32,
	ADD = 33,
	SUB = 34,
	MUL = 35,
	DIV = 36,
	MOD = 37,
	POW = 38,
	ADDK = 39,
	SUBK = 40,
	MULK = 41,
	DIVK = 42,
	MODK = 43,
	POWK = 44,
	AND = 45,
	OR = 46,
	ANDK = 47,
	ORK = 48,
	CONCAT = 49,
	NOT = 50,
	MINUS = 51,
	LENGTH = 52,
	NEWTABLE = 53,
	DUPTABLE = 54,
	SETLIST = 55,
	FORNPREP = 56,
	FORNLOOP = 57,
	FORGLOOP = 58,
	FORGPREP_INEXT = 59,
	FORGLOOP_INEXT = 60,
	FORGPREP_NEXT = 61,
	FORGLOOP_NEXT = 62,
	GETVARARGS = 63,
	DUPCLOSURE = 64,
	PREPVARARGS = 65,
	LOADKX = 66,
	JUMPX = 67,
	FASTCALL = 68,
	COVERAGE = 69,
	CAPTURE = 70,
	JUMPIFEQK = 71,
	JUMPIFNOTEQK = 72,
	FASTCALL1 = 73,
	FASTCALL2 = 74,
	FASTCALL2K = 75,
	FORGPREP = 76,
	JUMPXEQKNIL = 77,
	JUMPXEQKB = 78,
	JUMPXEQKN = 79,
	JUMPXEQKS = 80,
}

local fastcallNames = {
	[0] = "NONE",
	[1] = "ASSERT",
	[2] = "MATH_ABS",
	[3] = "MATH_ACOS",
	[4] = "MATH_ASIN",
	[5] = "MATH_ATAN2",
	[6] = "MATH_ATAN",
	[7] = "MATH_CEIL",
	[8] = "MATH_COSH",
	[9] = "MATH_COS",
	[10] = "MATH_DEG",
	[11] = "MATH_EXP",
	[12] = "MATH_FLOOR",
	[13] = "MATH_FMOD",
	[14] = "MATH_FREXP",
	[15] = "MATH_LDEXP",
	[16] = "MATH_LOG10",
	[17] = "MATH_LOG",
	[18] = "MATH_MAX",
	[19] = "MATH_MIN",
	[20] = "MATH_MODF",
	[21] = "MATH_POW",
	[22] = "MATH_RAD",
	[23] = "MATH_SINH",
	[24] = "MATH_SIN",
	[25] = "MATH_SQRT",
	[26] = "MATH_TANH",
	[27] = "MATH_TAN",
	[28] = "BIT32_ARSHIFT",
	[29] = "BIT32_BAND",
	[30] = "BIT32_BNOT",
	[31] = "BIT32_BOR",
	[32] = "BIT32_BXOR",
	[33] = "BIT32_BTEST",
	[34] = "BIT32_EXTRACT",
	[35] = "BIT32_LROTATE",
	[36] = "BIT32_LSHIFT",
	[37] = "BIT32_REPLACE",
	[38] = "BIT32_RROTATE",
	[39] = "BIT32_RSHIFT",
	[40] = "TYPE",
	[41] = "STRING_BYTE",
	[42] = "STRING_CHAR",
	[43] = "STRING_LEN",
	[44] = "TYPEOF",
	[45] = "STRING_SUB",
	[46] = "MATH_CLAMP",
	[47] = "MATH_SIGN",
	[48] = "MATH_ROUND",
	[49] = "RAWSET",
	[50] = "RAWGET",
	[51] = "RAWEQUAL",
	[52] = "TABLE_INSERT",
	[53] = "TABLE_UNPACK",
	[54] = "VECTOR",
	[55] = "BIT32_COUNTLZ",
	[56] = "BIT32_COUNTRZ",
	[57] = "SELECT_VARARG",
	[58] = "RAWLEN",
	[59] = "BIT32_EXTRACTK",
	[60] = "GETMETATABLE",
	[61] = "SETMETATABLE",
}

local function dissectImport(id, k)
	-- Import IDs have the top two bits as the length of the chain, and then 3 10-bit fields of constant string indices
	local count = bit32.rshift(id, 30)

	local k0 = k[bit32.extract(id, 20, 10) + 1]
	local k1 = count > 1 and k[bit32.extract(id, 10, 10) + 1]
	local k2 = count > 2 and k[bit32.band(id, 1023) + 1]

	local displayString = k0
	if k1 then
		displayString ..= "." .. k1
		if k2 then
			displayString ..= "." .. k2
		end
	end

	return {
		count = count,
		displayString = displayString,
	}
end

-- Takes a bytecode string and returns a proto table
local function deserialize(bytecode)
	local LBC_VERSION = 3

	-- Current read position in the bytecode string
	local offset = 1

	local function readByte()
		local number = string.byte(bytecode, offset, offset)
		offset += 1
		return number
	end

	local function readULEB128()
		local result = 0
		local b = 0 -- amount of bits to shift
		local c;

		repeat
			c = readByte()
			local c2 = bit32.band(c, 0x7F)
			result = bit32.bor(result, bit32.lshift(c2, b))
			b += 7
		until not bit32.btest(c, 0x80)

		return result
	end

	local function readUInt32()
		local number = string.unpack("<I", bytecode, offset)
		offset += 4
		return number
	end

	local function readFloat64()
		local number = string.unpack("<d", bytecode, offset)
		offset += 8
		return number
	end

	local function readLengthPrefixedString()
		local length = readULEB128()
		local str = string.unpack("c" .. length, bytecode, offset)
		offset += length
		return str
	end

	local bytecodeVersion = readByte()
	assert(bytecodeVersion ~= 0, "Cannot deserialize bytecode that is a compilation error")
	assert(
		bytecodeVersion == LBC_VERSION,
		string.format("Invalid bytecode version (must be %i, got %i)", LBC_VERSION, bytecodeVersion)
	)

	local stringCount = readULEB128()
	local stringTable = table.create(stringCount)
	if stringCount > 0 then
		for stringIdx = 1, stringCount do
			stringTable[stringIdx] = readLengthPrefixedString()
		end
	end

	local protoCount = readULEB128()
	local protoTable = table.create(protoCount)
	for protoIdx = 1, protoCount do
		local proto = {}

		proto.bytecodeOffset = offset - 1

		proto.maxstacksize = readByte()
		proto.numparams = readByte()
		proto.nups = readByte()
		proto.is_vararg = readByte()

		proto.sizecode = readULEB128()
		proto.startCodeBytecodeOffset = offset - 1
		proto.code = table.create(proto.sizecode)
		for codeIdx = 1, proto.sizecode do
			proto.code[codeIdx] = readUInt32()
		end

		proto.sizek = readULEB128()
		proto.k = table.create(proto.sizek)
		for kIdx = 1, proto.sizek do
			local kType = readByte()

			if kType == 0 then -- nil
				proto.k[kIdx] = nil
			elseif kType == 1 then -- boolean
				proto.k[kIdx] = readByte() ~= 0 -- 0 means false, 1 means true
			elseif kType == 2 then -- number
				proto.k[kIdx] = readFloat64() -- All Luau numbers are double-precision floats
			elseif kType == 3 then -- string
				proto.k[kIdx] = stringTable[readULEB128()]
			elseif kType == 4 then -- import
				proto.k[kIdx] = dissectImport(readUInt32(), proto.k) -- Import IDs are 32 bits wide
			elseif kType == 5 then -- table
				for _ = 1, readULEB128() do
					readULEB128()
				end
			elseif kType == 6 then -- closure
				proto.k[kIdx] = readULEB128() -- proto id
			else
				error(string.format("Unexpected constant type: %i is not a recognized type", kType))
			end
		end

		proto.sizep = readULEB128()
		proto.p = table.create(proto.sizep)
		for innerProtoIdx = 1, proto.sizep do
			proto.p[innerProtoIdx] = readULEB128()
		end

		proto.linedefined = readULEB128()

		local debugNameId = readULEB128()
		if debugNameId ~= 0 then
			proto.debugname = stringTable[debugNameId]
		end

		if readByte() ~= 0 then -- lineinfo?
			proto.linegaplog2 = readByte()

			local intervals = bit32.rshift(proto.sizecode - 1, proto.linegaplog2) + 1

			for _ = 1, proto.sizecode do
				readByte()
			end
			for _ = 1, intervals do
				readByte()
				readByte()
				readByte()
				readByte()
			end
		end

		if readByte() ~= 0 then -- debuginfo?
			proto.sizelocvars = readULEB128()
			for _ = 1, proto.sizelocvars do
				readULEB128()
				readULEB128()
				readULEB128()
				readByte()
			end

			proto.sizeupvalues = readULEB128()
			for _ = 1, proto.sizeupvalues do
				readULEB128()
			end
		end

		protoTable[protoIdx] = proto
	end

	local mainId = readULEB128()

	return protoTable, mainId
end

-- Functions to read an unsigned integer as a two's complement number
-- See https://en.wikipedia.org/wiki/Two%27s_complement
local function uint16_to_signed(n)
	local sign = bit32.btest(n, 0x8000)
	n = bit32.band(n, 0x7FFF)

	if sign then
		return n - 0x8000
	else
		return n
	end
end
local function uint24_to_signed(n)
	local sign = bit32.btest(n, 0x800000)
	n = bit32.band(n, 0x7FFFFF)

	if sign then
		return n - 0x800000
	else
		return n
	end
end

-- Functions to extract data from 32-bit instructions
-- Note that the instructions are decoded in little endian so the opcode is in the least significant byte
local function get_opcode(insn)
	return bit32.band(insn, 0xFF)
end
local function get_arga(insn)
	return bit32.band(bit32.rshift(insn, 8), 0xFF)
end
local function get_argb(insn)
	return bit32.band(bit32.rshift(insn, 16), 0xFF)
end
local function get_argc(insn)
	return bit32.rshift(insn, 24)
end
local function get_argd(insn)
	return uint16_to_signed(bit32.rshift(insn, 16))
end
local function get_arge(insn)
	return uint24_to_signed(bit32.rshift(insn, 8))
end

-- Takes a value from the constant table and makes a string from it
local function getConstantString(constant)
	local constantString;

	local constantType = type(constant)
	if constantType == "nil" then
		constantString = "nil"
	elseif constantType == "boolean" then
		constantString = constant and "true" or "false"
	elseif constantType == "number" then
		constantString = string.format("%.17g", constant)
	elseif constantType == "string" then
		-- Safely escape control characters
		constantString = "'" .. string.format(
			"%s",
			(string.gsub(
				constant,
				"[%c\"\\]",
				{
					["\n"] = "\\n",
					["\t"] = "\\t",
					["\a"] = "\\a",
					["\b"] = "\\b",
					["\v"] = "\\v",
					["\f"] = "\\f",
					["\r"] = "\\r",
					["\\"] = "\\\\",
					["\""] = "\\\"",
				}
			))
		) .. "'"
	else
		constantString = string.format("unknown constant of type %s", constantType)
	end

	return constantString
end

local function disassemble(bytecodeString, options)
	-- If a Script instance was inputted, get its bytecode first
	if typeof(bytecodeString) == "Instance" then
		if bytecodeString:IsA("LuaSourceContainer") then
			bytecodeString = getscriptbytecode(bytecodeString)
		else
			error("Argument #1 to `disassemble` must be a Script instance")
		end
	elseif type(bytecodeString) ~= "string" then
		error("Argument #1 to `disassemble` must be a string")
	end

	options = options or {}
	local showBytecodeOffsets = options.showBytecodeOffsets or false
	local showRawBytes = options.showRawBytes or false
	local useRobloxOpcodes = options.useRobloxOpcodes or true

	local opcodes = vanillaOpcodes
	if useRobloxOpcodes then
		-- there be dragons if modifying a table while iterating over it :skull:
		local robloxOpcodes = {}
		for name, byte in pairs(opcodes) do
			-- uint8_t(op * 227)
			robloxOpcodes[name] = bit32.band(byte * 227, 0xff)
		end
		opcodes = robloxOpcodes
	end

	local CAPTURE_TYPE_NAMES = {
		[0] = "VAL",
		[1] = "REF",
		[2] = "UPVAL",
	}

	local protoOutputs = {}

	local protoTable, mainProtoId = deserialize(bytecodeString)

	for protoId, proto in ipairs(protoTable) do
		local output = {}
		protoOutputs[protoId] = output

		-- Write proto header
		table.insert(output, string.format("; bytecode proto index: %i\n", protoId - 1))
		if showBytecodeOffsets then
			table.insert(output, string.format("; bytecode offset: 0x%X\n", proto.bytecodeOffset))
		end
		if proto.linedefined then
			table.insert(output, string.format("; line defined: %i\n", proto.linedefined))
		end
		if proto.debugname then
			table.insert(output, string.format("; proto name: %s\n\n", proto.debugname))
		elseif protoId - 1 == mainProtoId then -- Is this the main proto?
			table.insert(output, "; main proto\n\n")
		else
			table.insert(output, "\n")
		end

		table.insert(output, string.format("; maxstacksize: %i\n", proto.maxstacksize))
		table.insert(output, string.format("; numparams: %i\n", proto.numparams))
		table.insert(output, string.format("; nups: %i\n", proto.nups))
		table.insert(output, string.format("; is_vararg: %i\n", proto.is_vararg))

		if #proto.p > 0 then
			table.insert(output, string.format("; child protos: %s\n\n", table.concat(proto.p, ", ")))
		end

		table.insert(output, string.format("; sizecode: %i\n", proto.sizecode))
		table.insert(output, string.format("; sizek: %i\n\n", proto.sizek))

		-- Loop over code until end is reached
		-- A while loop is used here instead of a for loop to make it easier to control the pc variable
		local pc = 1
		while pc <= proto.sizecode do
			local insn = proto.code[pc]
			local opcode = get_opcode(insn)

			if opcode == opcodes.PREPVARARGS then
				pc += 1
				continue
			end

			local bytecodeOffsetString = ""
			if showBytecodeOffsets then
				bytecodeOffsetString = string.format("[%X] ", proto.startCodeBytecodeOffset + pc - 1)
			end

			-- The instruction index must be shown with at least 3 digits
			local insnIdxString = string.format("[%03i] ", pc - 1)

			local rawBytesString = ""
			if showRawBytes then
				rawBytesString = string.format("%08X ", insn)
			end

			-- TODO: try using an array with function handlers for opcodes instead of using a large if/elseif block
			local insnText
			if opcode == opcodes.NOP then
				insnText = string.format("NOP (%#010x)\n", insn)
			elseif opcode == opcodes.BREAK then
				insnText = "BREAK\n"
			elseif opcode == opcodes.LOADNIL then
				insnText = string.format("LOADNIL R%i\n", get_arga(insn))
			elseif opcode == opcodes.LOADB then
				local targetRegister = get_arga(insn)
				local boolValue = get_argb(insn)
				local jumpOffset = get_argc(insn)

				if jumpOffset > 0 then
					insnText = string.format(
						"LOADB R%i %s %+i ; jump to %i\n",
						targetRegister,
						boolValue ~= 0 and "true" or "false",
						jumpOffset,
						pc + jumpOffset
					)
				else
					insnText = string.format(
						"LOADB R%i %s\n",
						targetRegister,
						boolValue ~= 0 and "true" or "false"
					)
				end
			elseif opcode == opcodes.LOADN then
				insnText = string.format(
					"LOADN R%i %i\n",
					get_arga(insn),
					get_argd(insn)
				)
			elseif opcode == opcodes.LOADK then
				local constantIndex = get_argd(insn)
				local constant = proto.k[constantIndex + 1]
				local constantString = getConstantString(constant)

				insnText = string.format(
					"LOADK R%i K%i [%s]\n",
					get_arga(insn),
					constantIndex,
					constantString
				)
			elseif opcode == opcodes.MOVE then
				insnText = string.format(
					"MOVE R%i R%i\n",
					get_arga(insn),
					get_argd(insn)
				)
			elseif opcode == opcodes.GETGLOBAL then
				pc += 1
				local target = get_arga(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"GETGLOBAL R%i K%i [%s]\n",
					target,
					aux,
					getConstantString(proto.k[aux + 1])
				)
			elseif opcode == opcodes.SETGLOBAL then
				pc += 1
				local source = get_arga(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"SETGLOBAL R%i K%i [%s]\n",
					source,
					aux,
					getConstantString(proto.k[aux + 1])
				)
			elseif opcode == opcodes.GETUPVAL then
				insnText = string.format(
					"GETUPVAL R%i %i\n",
					get_arga(insn),
					get_argb(insn)
				)
			elseif opcode == opcodes.SETUPVAL then
				insnText = string.format(
					"SETUPVAL R%i %i\n",
					get_arga(insn),
					get_argb(insn)
				)
			elseif opcode == opcodes.CLOSEUPVALS then
				insnText = string.format("CLOSEUPVALS R%i\n", get_arga(insn))
			elseif opcode == opcodes.GETIMPORT then
				pc += 1 -- skip aux
				local target = get_arga(insn)
				local constantIndex = get_argd(insn)
				local import = proto.k[constantIndex + 1]
				insnText = string.format(
					"GETIMPORT R%i %i [%s]\n",
					target,
					constantIndex,
					import.displayString
				)
			elseif opcode == opcodes.GETTABLE then
				insnText = string.format(
					"GETTABLE R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.SETTABLE then
				insnText = string.format(
					"SETTABLE R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.GETTABLEKS then
				pc += 1
				local targetRegister = get_arga(insn)
				local tableRegister = get_argb(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"GETTABLEKS R%i R%i K%i [%s]\n",
					targetRegister,
					tableRegister,
					aux,
					getConstantString(proto.k[aux + 1])
				)
			elseif opcode == opcodes.SETTABLEKS then
				pc += 1
				local sourceRegister = get_arga(insn)
				local tableRegister = get_argb(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"SETTABLEKS R%i R%i K%i [%s]\n",
					sourceRegister,
					tableRegister,
					aux,
					getConstantString(proto.k[aux + 1])
				)
			elseif opcode == opcodes.GETTABLEN then
				local argc = get_argc(insn)
				insnText = string.format(
					"GETTABLEN R%i R%i %i\n",
					get_arga(insn),
					get_argb(insn),
					argc + 1
				)
			elseif opcode == opcodes.SETTABLEN then
				local argc = get_argc(insn)
				insnText = string.format(
					"SETTABLEN R%i R%i %i\n",
					get_arga(insn),
					get_argb(insn),
					argc + 1
				)
			elseif opcode == opcodes.NEWCLOSURE then
				local childProtoId = get_argd(insn)
				insnText = string.format(
					"NEWCLOSURE R%i P%i ; bytecode proto index = %i\n",
					get_arga(insn),
					childProtoId,
					proto.p[childProtoId + 1]
				)
			elseif opcode == opcodes.NAMECALL then
				pc += 1
				local targetRegister = get_arga(insn)
				local sourceRegister = get_argb(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"NAMECALL R%i R%i K%i [%s]\n",
					targetRegister,
					sourceRegister,
					aux,
					getConstantString(proto.k[aux + 1])
				)
			elseif opcode == opcodes.CALL then
				local nargs = get_argb(insn)
				local nresults = get_argc(insn)

				insnText = string.format(
					"CALL R%i %i %i\n",
					get_arga(insn),
					nargs - 1,
					nresults - 1
				)
			elseif opcode == opcodes.RETURN then
				local arga = get_arga(insn)
				local argb = get_argb(insn)
				insnText = string.format(
					"RETURN R%i %i\n",
					arga,
					argb - 1
				)
			elseif opcode == opcodes.JUMP then
				local offset = get_argd(insn)
				insnText = string.format(
					"JUMP %+i ; to %i\n",
					offset,
					pc + offset
				)
			elseif opcode == opcodes.JUMPBACK then
				local offset = get_argd(insn)
				insnText = string.format(
					"JUMPBACK %+i ; to %i\n",
					offset,
					pc + offset
				)
			elseif opcode == opcodes.JUMPIF then
				local sourceRegister = get_arga(insn)
				local offset = get_argd(insn)
				insnText = string.format(
					"JUMPIF R%i %+i ; to %i\n",
					sourceRegister,
					offset,
					pc + offset
				)
			elseif opcode == opcodes.JUMPIFNOT then
				local sourceRegister = get_arga(insn)
				local offset = get_argd(insn)
				insnText = string.format(
					"JUMPIFNOT R%i %+i ; to %i\n",
					sourceRegister,
					offset,
					pc + offset
				)
			elseif opcode == opcodes.JUMPIFEQ then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFEQ R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPIFLE then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFLE R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPIFLT then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFLT R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPIFNOTEQ then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFNOTEQ R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPIFNOTLE then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFNOTLE R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPIFNOTLT then
				local register1 = get_arga(insn)
				local offset = get_argd(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"JUMPIFNOTLT R%i R%i %+i ; to %i\n",
					register1,
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.ADD then
				insnText = string.format(
					"ADD R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.SUB then
				insnText = string.format(
					"SUB R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.MUL then
				insnText = string.format(
					"MUL R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.DIV then
				insnText = string.format(
					"DIV R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.MOD then
				insnText = string.format(
					"MOD R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.POW then
				insnText = string.format(
					"POW R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.ADDK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"ADDK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.SUBK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"SUBK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.MULK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"MULK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.DIVK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"DIVK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.MODK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"MODK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.POWK then
				local constantIndex = get_argc(insn)
				local constantValue = proto.k[constantIndex + 1]
				insnText = string.format(
					"POWK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(constantValue)
				)
			elseif opcode == opcodes.AND then
				insnText = string.format(
					"AND R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.OR then
				insnText = string.format(
					"OR R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.ANDK then
				local constantIndex = get_argc(insn)
				insnText = string.format(
					"ANDK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(proto.k[constantIndex + 1])
				)
			elseif opcode == opcodes.ORK then
				local constantIndex = get_argc(insn)
				insnText = string.format(
					"ORK R%i R%i K%i [%s]\n",
					get_arga(insn),
					get_argb(insn),
					constantIndex,
					getConstantString(proto.k[constantIndex + 1])
				)
			elseif opcode == opcodes.CONCAT then
				insnText = string.format(
					"CONCAT R%i R%i R%i\n",
					get_arga(insn),
					get_argb(insn),
					get_argc(insn)
				)
			elseif opcode == opcodes.NOT then
				insnText = string.format(
					"NOT R%i R%i\n",
					get_arga(insn),
					get_argb(insn)
				)
			elseif opcode == opcodes.MINUS then
				insnText = string.format(
					"MINUS R%i R%i\n",
					get_arga(insn),
					get_argb(insn)
				)
			elseif opcode == opcodes.LENGTH then
				insnText = string.format(
					"LENGTH R%i R%i\n",
					get_arga(insn),
					get_argb(insn)
				)
			elseif opcode == opcodes.NEWTABLE then
				pc += 1
				local aux = proto.code[pc]
				local argb = get_argb(insn)
				insnText = string.format(
					"NEWTABLE R%i %i %i\n",
					get_arga(insn),
					argb == 0 and 0 or 2^(argb - 1),
					aux
				)
			elseif opcode == opcodes.DUPTABLE then
				insnText = string.format(
					"DUPTABLE R%i %i\n",
					get_arga(insn),
					get_argd(insn)
				)
			elseif opcode == opcodes.SETLIST then
				pc += 1
				local sourceStart = get_argb(insn)
				local argc = get_argc(insn)
				local aux = proto.code[pc]
				insnText = string.format(
					"SETLIST R%i R%i %i [%i]\n",
					get_arga(insn),
					sourceStart,
					argc - 1,
					aux
				)
			elseif opcode == opcodes.FORNPREP then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORNPREP R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORNLOOP then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORNLOOP R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORGPREP then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORGPREP R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORGLOOP then
				local jumpOffset = get_argd(insn)
				local jumpTo = pc + jumpOffset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"FORGLOOP R%i %+i %i%s ; to %i\n",
					get_arga(insn),
					jumpOffset,
					bit32.band(aux, 0xff),
					bit32.btest(aux, 0x80000000) and " [inext]" or "", -- High bit
					jumpTo
				)
			elseif opcode == opcodes.FORGPREP_INEXT then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORGPREP_INEXT R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORGLOOP_INEXT then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORGLOOP_INEXT R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORGPREP_NEXT then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORGPREP_NEXT R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.FORGLOOP_NEXT then
				local jumpOffset = get_argd(insn)
				insnText = string.format(
					"FORGLOOP_NEXT R%i %+i ; to %i\n",
					get_arga(insn),
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.GETVARARGS then
				local argb = get_argb(insn)
				insnText = string.format(
					"GETVARARGS R%i %i\n",
					get_arga(insn),
					argb - 1
				)
			elseif opcode == opcodes.DUPCLOSURE then
				local childProtoId = get_argd(insn)
				insnText = string.format(
					"DUPCLOSURE R%i K%i ; bytecode proto index = %i\n",
					get_arga(insn),
					childProtoId,
					proto.k[childProtoId + 1]
				)
			elseif opcode == opcodes.LOADKX then
				pc += 1
				local constantIndex = proto.code[pc] -- aux
				local constant = proto.k[constantIndex + 1]
				local constantString = getConstantString(constant)
				insnText = string.format(
					"LOADKX R%i K%i [%s]\n",
					get_arga(insn),
					constantIndex,
					constantString
				)
			elseif opcode == opcodes.JUMPX then
				local offset = get_arge(insn)
				insnText = string.format(
					"JUMPX %+i ; to %i\n",
					offset,
					pc + offset
				)
			elseif opcode == opcodes.FASTCALL then
				local jumpOffset = get_argc(insn)
				local fid = get_arga(insn)
				insnText = string.format(
					"FASTCALL %s %+i ; to %i\n",
					fastcallNames[fid],
					jumpOffset,
					pc + jumpOffset
				)
			elseif opcode == opcodes.COVERAGE then
				insnText = "COVERAGE\n"
			elseif opcode == opcodes.CAPTURE then
				local captureTypeId = get_arga(insn)
				local captureTypeString = CAPTURE_TYPE_NAMES[captureTypeId]
				insnText = string.format(
					captureTypeString ~= "UPVAL" and "CAPTURE %s R%i\n" or "CAPTURE %s U%i\n",
					captureTypeString,
					get_argb(insn)
				)
			elseif opcode == opcodes.FASTCALL1 then
				local fid = get_arga(insn)
				local offset = get_argc(insn)
				insnText = string.format(
					"FASTCALL1 %s R%i %+i ; to %i\n",
					fastcallNames[fid],
					get_argb(insn),
					offset,
					pc + offset
				)
			elseif opcode == opcodes.FASTCALL2 then
				local fid = get_arga(insn)
				local offset = get_argc(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"FASTCALL2 %s R%i R%i %+i ; to %i\n",
					fastcallNames[fid],
					get_argb(insn),
					aux,
					offset,
					jumpTo
				)
			elseif opcode == opcodes.FASTCALL2K then
				local fid = get_arga(insn)
				local offset = get_argc(insn)
				local jumpTo = pc + offset
				pc += 1
				local aux = proto.code[pc]
				insnText = string.format(
					"FASTCALL2K %s R%i K%i %+i [%s] ; to %i\n",
					fastcallNames[fid],
					get_argb(insn),
					aux,
					offset,
					getConstantString(proto.k[aux + 1]),
					jumpTo
				)
			elseif opcode == opcodes.JUMPXEQKNIL then
				local sourceRegister1 = get_arga(insn)
				local jumpOffset = get_argd(insn)
				local jumpTo = pc + jumpOffset
				pc += 1
				local aux = proto.code[pc]
				local notFlag = bit32.btest(aux, 0x80000000)
				insnText = string.format(
					"JUMP%sEQKNIL R%i %+i ; to %i\n",
					notFlag and "IFNOT" or "IF",
					sourceRegister1,
					jumpOffset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPXEQKB then
				local sourceRegister1 = get_arga(insn)
				local jumpOffset = get_argd(insn)
				local jumpTo = pc + jumpOffset
				pc += 1
				local aux = proto.code[pc]
				local boolValue = bit32.btest(aux, 1)
				local notFlag = bit32.btest(aux, 0x80000000)
				insnText = string.format(
					"JUMP%sEQKB R%i %s %+i ; to %i\n",
					notFlag and "IFNOT" or "IF",
					sourceRegister1,
					boolValue and "true" or "false",
					jumpOffset,
					jumpTo
				)
			elseif opcode == opcodes.JUMPXEQKN then
				local sourceRegister1 = get_arga(insn)
				local jumpOffset = get_argd(insn)
				local jumpTo = pc + jumpOffset
				pc += 1
				local aux = proto.code[pc]
				local kIdx = bit32.band(aux, 0x00FFFFFF)
				local notFlag = bit32.btest(aux, 0x80000000)
				insnText = string.format(
					"JUMP%sEQKN R%i K%i %+i [%s] ; to %i\n",
					notFlag and "IFNOT" or "IF",
					sourceRegister1,
					kIdx,
					jumpOffset,
					getConstantString(proto.k[kIdx + 1]),
					jumpTo
				)
			elseif opcode == opcodes.JUMPXEQKS then
				local sourceRegister1 = get_arga(insn)
				local jumpOffset = get_argd(insn)
				local jumpTo = pc + jumpOffset
				pc += 1
				local aux = proto.code[pc]
				local kIdx = bit32.band(aux, 0x00FFFFFF)
				local notFlag = bit32.btest(aux, 0x80000000)
				insnText = string.format(
					"JUMP%sEQKS R%i K%i %+i [%s] ; to %i\n",
					notFlag and "IFNOT" or "IF",
					sourceRegister1,
					kIdx,
					jumpOffset,
					getConstantString(proto.k[kIdx + 1]),
					jumpTo
				)
			else -- Unknown opcode
				-- Show the hex of this instruction so the user knows what the disassembler failed to recognize
				insnText = string.format("UNKNOWN %08X\n", insn)
			end

			table.insert(output, bytecodeOffsetString .. insnIdxString .. rawBytesString .. insnText)

			pc += 1
		end
	end

	-- Final step, join all outputs together in a nice hierarchical fashion

	local finalOutput = {} -- TODO TODO TODODSHOGDHKODHH CALCULATE SIZE NEEDED
	local level = 0
	local function traverse(protoId)
		local proto = protoTable[protoId]
		local thisOutput = protoOutputs[protoId]

		for _, item in ipairs(thisOutput) do
			table.insert(
				finalOutput,
				string.rep("\t", level) .. item
			)
		end

		level += 1
		for _, childId in ipairs(proto.p) do
			traverse(childId + 1)
		end
		level -= 1
	end

	traverse(mainProtoId + 1)

	return table.concat(finalOutput, "")
end

if IS_ROBLOX_CLIENT then
	getgenv().disassemble = disassemble
end

return disassemble
