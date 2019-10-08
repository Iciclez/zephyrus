#include "disassembler.hpp"

#if defined(CAPSTONE_DISASSEMBLER) || defined(ZYDIS_DISASSEMBLER)

#include "zephyrus.hpp"
#include <fstream>
#include <iterator>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

#ifdef CAPSTONE_DISASSEMBLER
#ifdef X86
#pragma comment(lib, "capstone.lib")
#elif X64
#pragma comment(lib, "capstone64.lib")
#else
#pragma comment(lib, "capstone.lib")
#endif
#elif ZYDIS_DISASSEMBLER
#ifdef X86
#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "Zycore.lib")
#elif X64
#pragma comment(lib, "Zydis64.lib")
#pragma comment(lib, "Zycore64.lib")
#else
#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "Zycore.lib")
#endif
#endif

disassembler::disassembler(uint64_t address, const std::vector<uint8_t>& bytecode, disassembler_mode mode)
	: bytecode(bytecode), mode(mode), address(address)
{

#ifdef CAPSTONE_DISASSEMBLER
	cs_mode m = CS_MODE_32;

	switch (mode)
	{
	case x86:
		m = CS_MODE_32;
		break;

	case x64:
		m = CS_MODE_64;
		break;
	}

	cs_open(CS_ARCH_X86, m, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

	this->size = cs_disasm(handle, bytecode.data(), bytecode.size(), address, 0, &array_of_instruction);

	this->instructions.reserve(this->size);

	for (size_t n = 0; n < this->size; ++n)
	{
		this->instructions.push_back(this->array_of_instruction[n]);
		this->instructions_address.push_back(this->array_of_instruction[n].address);
		this->instructions_bytecode.push_back(std::vector<uint8_t>(this->array_of_instruction[n].bytes, this->array_of_instruction[n].bytes + this->array_of_instruction[n].size));
	}

#elif ZYDIS_DISASSEMBLER
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	switch (mode)
	{
	case x86:
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
		break;

	case x64:
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		break;
}

	this->size = 0;
	for (size_t n = 0; n < this->bytecode.size();)
	{
		ZydisDecodedInstruction instruction;

		ZyanStatus status = ZydisDecoderDecodeBuffer(&decoder, this->bytecode.data() + n, this->bytecode.size() - n, &instruction);
		if (status != ZYDIS_STATUS_NO_MORE_DATA)
		{
			this->instructions.push_back(instruction);
			this->instructions_address.push_back(this->address + n);
			this->instructions_bytecode.push_back(std::vector<uint8_t>(this->bytecode.data() + n, this->bytecode.data() + n + instruction.length));

			n += instruction.length;
			this->size += instruction.length;
		}

		if (!ZYAN_SUCCESS(status))
		{
			++n;
		}
	}
#endif
}

disassembler::~disassembler() noexcept
{
#ifdef CAPSTONE_DISASSEMBLER
	cs_free(array_of_instruction, size);
	cs_close(&handle);
#endif
}

size_t disassembler::get_size() const
{
	return this->size;
}

std::vector<instruction> disassembler::get_instructions() const
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
#ifdef CAPSTONE_DISASSEMBLER
	std::stringstream stream;

	for (size_t n = 0; n < this->size; ++n)
	{
		stream << begin << this->instructions.at(n).mnemonic << ' ' << this->instructions.at(n).op_str << end;

		if (n + 1 != this->size)
		{
			stream << separator;
		}
	}

	std::string result(stream.str());

	std::transform(result.begin(), result.end(), result.begin(), toupper);

	return result;
#elif ZYDIS_DISASSEMBLER
	char buffer[256];
	size_t offset = 0;
	std::stringstream stream;

	for (size_t n = 0; n < this->instructions.size(); ++n)
	{
		ZydisFormatterFormatInstruction(&formatter, &this->instructions.at(n), buffer, sizeof(buffer), address + offset);
		stream << begin << buffer << end;

		offset += this->instructions.at(n).length;

		if (n + 1 != this->size)
		{
			stream << separator;
		}
}

	std::string result(stream.str());

	std::transform(result.begin(), result.end(), result.begin(), ::toupper);

	return result;
#endif
}

std::vector<uint8_t> disassembler::get_bytecode() const
{
	return this->bytecode;
}

#endif