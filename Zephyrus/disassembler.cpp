#include "disassembler.hpp"

#include "zephyrus.hpp"
#include <fstream>
#include <iterator>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

disassembler::disassembler(uint64_t address, const std::vector<uint8_t>& bytecode, disassembler_mode mode)
	: bytecode(bytecode), mode(mode), address(address)
{
	ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;

	switch (mode)
	{
	case x86:
		machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
		break;

	case x64:
		machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
		break;
	}

	size_t offset = 0;
	ZydisDisassembledInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(machine_mode, address, this->bytecode.data() + offset, this->bytecode.size() - offset, &instruction))) 
	{
		this->instructions.push_back(instruction);
		this->instructions_address.push_back(this->address + offset);
		this->instructions_bytecode.push_back(std::vector<uint8_t>(this->bytecode.data() + offset, this->bytecode.data() + offset + instruction.info.length));

		offset += instruction.info.length;
		this->size += instruction.info.length;
	}
}

disassembler::~disassembler() noexcept
{
}

size_t disassembler::get_size() const
{
	return this->size;
}

std::vector<ZydisDisassembledInstruction> disassembler::get_instructions() const
{
	return this->instructions;
}

std::vector<uint64_t> disassembler::get_instructions_address() const
{
	return this->instructions_address;
}

std::vector<std::vector<uint8_t>> disassembler::get_instructions_bytecode() const
{
	return this->instructions_bytecode;
}

std::string disassembler::get_instructions_string(const std::string& separator, const std::string& begin, const std::string& end) const
{
	std::stringstream stream;

	for (size_t n = 0; n < this->instructions.size(); ++n)
	{
		stream << begin << this->instructions.at(n).text << end;

		if (n + 1 != this->size)
		{
			stream << separator;
		}
}

	std::string result(stream.str());

	std::transform(result.begin(), result.end(), result.begin(), ::toupper);

	return result;
}

std::vector<uint8_t> disassembler::get_bytecode() const
{
	return this->bytecode;
}
