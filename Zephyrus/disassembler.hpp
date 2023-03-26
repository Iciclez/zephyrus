#pragma once

#define ZYDIS_STATIC_BUILD
#define ZYCORE_STATIC_BUILD

#include "Zydis.h"

#include <cstdint>
#include <vector>
#include <string>



class disassembler
{
public:
	enum disassembler_mode : int32_t
	{
		x86 = 1,
		x64
	};

	disassembler(uint64_t address, const std::vector<uint8_t> &bytecode, disassembler_mode mode = x86);
	~disassembler() noexcept;

	size_t get_size() const;

	std::vector<ZydisDisassembledInstruction> get_instructions() const;
	std::vector<uint64_t> get_instructions_address() const;
	std::vector<std::vector<uint8_t>> get_instructions_bytecode() const;
	std::string get_instructions_string(const std::string& separator = "\n", const std::string& begin = "", const std::string& end = "") const;

	std::vector<uint8_t> get_bytecode() const;

private:
	uint64_t address;
	size_t size;
	std::vector<ZydisDisassembledInstruction> instructions;
	std::vector<uint64_t> instructions_address;
	std::vector<std::vector<uint8_t>> instructions_bytecode;
	std::vector<uint8_t> bytecode;
	disassembler_mode mode;
};
