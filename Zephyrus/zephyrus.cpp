#include "zephyrus.hpp"

#include <windows.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>

#include "assembler.hpp"
#include "disassembler.hpp"
#include "detours.h"

#ifdef X86
#pragma comment (lib, "detours.lib")
#elif X64
#pragma comment (lib, "detours64.lib")
#else
#pragma comment (lib, "detours.lib")
#endif

zephyrus::zephyrus(padding_byte padding)
	: padding(padding)
{
	this->pageexecutereadwrite = [&](address_t address, size_t size, const std::function<void(void)> &function)
	{
		DWORD protect = 0;

		if (!this->pagereadwriteaccess(address))
		{
			protect = this->protectvirtualmemory(address, size);
		}

		function();

		if (protect)
		{
			return VirtualProtect(reinterpret_cast<void*>(address), size, protect, &protect) != FALSE;
		}

		return true;
	};

	HANDLE process = GetCurrentProcess();
	HANDLE token = 0;
	if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &token))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	LUID luid = { 0 };
	if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", &luid))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	TOKEN_PRIVILEGES privileges = { 0 };
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, false, &privileges, 0, 0, 0);

	CloseHandle(token);
	CloseHandle(process);
}

zephyrus::~zephyrus() noexcept
{
}

bool zephyrus::pagereadwriteaccess(address_t address)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
	{
		return false;
	}

	if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
	{
		return false;
	}

	if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
	{
		return false;
	}

	return true;
}

uint32_t zephyrus::protectvirtualmemory(address_t address, size_t size)
{
	DWORD protection = 0;
	return VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &protection) ? protection : 0;
}

const std::vector<uint8_t> zephyrus::readmemory(address_t address, size_t size)
{
	std::vector<uint8_t> memory;
	memory.reserve(size);

	this->pageexecutereadwrite(address, size, [&]()
	{
		for (size_t i = 0; i < size; i++)
		{
			memory.push_back(*reinterpret_cast<uint8_t*>(address + i));
		}
	});

	return memory;
}

bool zephyrus::writememory(address_t address, const std::string & array_of_bytes, size_t padding_size, bool retain_bytes)
{
	std::vector<uint8_t> data = string_to_bytes(array_of_bytes);
	
	data.insert(data.end(), padding_size, static_cast<uint8_t>(padding));

	return this->writememory(address, data, retain_bytes);
}

bool zephyrus::writememory(address_t address, const std::vector<uint8_t>& bytes, bool retain_bytes)
{
	return this->pageexecutereadwrite(address, bytes.size(), [&]()
	{
		if (retain_bytes)
		{
			memory_patches[address] = this->readmemory(address, bytes.size());
		}

		for (size_t i = 0; i < bytes.size(); ++i)
		{
			*reinterpret_cast<uint8_t*>(address + i) = bytes.at(i);
		}

	});
}

bool zephyrus::copymemory(address_t address, void *bytes, size_t size, bool retain_bytes)
{
	return this->pageexecutereadwrite(address, size, [&]()
	{
		if (retain_bytes)
		{
			memory_patches[address] = this->readmemory(address, size);
		}

		memcpy(reinterpret_cast<void*>(address), bytes, size);
	});
}

bool zephyrus::writeassembler(address_t address, const std::string & assembler_code, bool retain_bytes)
{
	std::vector<uint8_t> bytecodes;

	if (!this->assemble(assembler_code, bytecodes))
	{
		return false;
	}

	return this->writememory(address, bytecodes, retain_bytes);
}

bool zephyrus::writepadding(address_t address, size_t padding_size)
{
	std::vector<uint8_t> padding_bytes;

	padding_bytes.resize(padding_size, static_cast<uint8_t>(padding));

	return this->writememory(address, padding_bytes, false);
}

bool zephyrus::revertmemory(address_t address)
{
	try
	{
		return this->writememory(address, memory_patches.at(address), false);
	}
	catch (std::exception &)
	{
		return false;
	}
}

bool zephyrus::redirect(hook_operation operation, address_t * address, address_t function, bool enable)
{
	if (enable)
	{
		size_t size = 5 + (operation > 0xff ? 1 : 0) + this->getnopcount(*address, operation);

#ifdef X86
		size_t JMP_SIZE = 5;
#elif X64
		size_t JMP_SIZE = 14;
#endif

		//insert trampoline (orig function bytes)
		std::vector<uint8_t> trampoline = this->readmemory(*address, size);

		//add jmp at end of original bytes
		trampoline.resize(trampoline.size() + JMP_SIZE);
		this->trampoline_table[*address] = trampoline;
		this->sethook(
#ifdef X86
			JMP
#elif X64
			JMP_64
#endif
			, reinterpret_cast<address_t>(this->trampoline_table[*address].data() + this->trampoline_table[*address].size() - JMP_SIZE),
			*address + size, 0, false);

		//enable page_readwrite_execute in trampoline
		this->protectvirtualmemory(reinterpret_cast<address_t>(this->trampoline_table[*address].data()), this->trampoline_table[*address].size());

		//relocate address ptr to trampoline function
		this->trampoline_detour[reinterpret_cast<address_t>(this->trampoline_table[*address].data())] = std::make_pair(*address, 0);
		*address = reinterpret_cast<address_t>(this->trampoline_table[*address].data());

#ifdef X86

		return this->sethook(operation, this->trampoline_detour[*address].first, function);

#elif X64
		
		this->trampoline_detour[*address].second = reinterpret_cast<address_t>(
			DetourAllocateRegionWithinJumpBounds(
					reinterpret_cast<void*>(this->trampoline_detour[*address].first), 
					reinterpret_cast<PDWORD>(&JMP_SIZE)
			));
		this->sethook(JMP_64, this->trampoline_detour[*address].second, function, 0, false);

		return this->sethook(operation, this->trampoline_detour[*address].first, this->trampoline_detour[*address].second);

#endif
	}

	//restores address from our trampoline detour
	*address = this->trampoline_detour[*address].first;

	//remove trampoline_detour and trampoline_table

	for (auto it = this->trampoline_detour.begin(); it != this->trampoline_detour.end(); ++it)
	{
		//std::pair<> of relocated_address to our real_address
		if ((*it).second.first == *address)
		{
#ifdef X64
			VirtualFree(reinterpret_cast<void*>((*it).second.second), 0, MEM_RELEASE);
#elif X86
			//pair<>::second is unused
#endif
			this->trampoline_detour.erase(it);
		}
	}

	for (auto it = this->trampoline_table.begin(); it != this->trampoline_table.end(); ++it)
	{
		//std::pair<> of real_address to trampoline bytes
		if ((*it).first == *address)
		{
			this->trampoline_table.erase(it);
		}
	}

	return this->revertmemory(*address);
}

bool zephyrus::redirect(address_t * address, address_t function, bool enable)
{
	return this->redirect(JMP, address, function, enable);
}

bool zephyrus::detour(void ** from, void *to, bool enable)
{
	if (DetourTransactionBegin() != NO_ERROR)
	{
		return false;
	}

	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
	{
		DetourTransactionAbort();
		return false;
	}

	if ((enable ? DetourAttach : DetourDetach)(from, to) != NO_ERROR)
	{
		DetourTransactionAbort();
		return false;
	}

	return DetourTransactionCommit() == NO_ERROR;
}

bool zephyrus::sethook(hook_operation operation, address_t address, address_t function, size_t nop_count, bool retain_bytes)
{
	if (nop_count == -1)
	{
		nop_count = this->getnopcount(address, operation);
	}

	int32_t i = operation > 0xff ? 1 : 0;
	size_t size = 5 + i + nop_count;

	//handle x64 instruction
	if (operation == JMP_64)
	{
		size = 14 + nop_count;
	}
	else if (operation == CALL_64)
	{
		size = 16 + nop_count;
	}


	return this->pageexecutereadwrite(address, size, [&]()
	{
		if (retain_bytes)
		{
			memory_patches[address] = this->readmemory(address, size);
		}

		if (operation == JMP_64)
		{
			*reinterpret_cast<address_t*>(address) = 0x0000000025FF;
			*reinterpret_cast<address_t*>(address + 6) = function;
		}
		else if (operation == CALL_64)
		{
			*reinterpret_cast<address_t*>(address) = CALL_64;
			*reinterpret_cast<address_t*>(address + 8) = function;
		}
		else
		{
			//maximum of 4 bytes address can use this case
			*reinterpret_cast<uint32_t*>(address) = operation;
			*reinterpret_cast<uint32_t*>(address + 1 + i) = static_cast<uint32_t>(function - address - 5 - i);
		}

		this->writepadding(address + size - nop_count, nop_count);
	});
}

bool zephyrus::sethook(hook_operation operation, address_t address, const std::string & assembler_code, size_t nop_count, bool retain_bytes)
{
	std::vector<uint8_t> bytecodes;
	
	if (!this->assemble(assembler_code, bytecodes))
	{
		return false;
	}

	this->hook_memory[address] = bytecodes;

	return this->sethook(operation, address, reinterpret_cast<address_t>(this->hook_memory[address].data()), nop_count, retain_bytes);
}

bool zephyrus::sethook(hook_operation operation, address_t address, const std::vector<std::string>& assembler_code, size_t nop_count, bool retain_bytes)
{
	std::string assembler = "";

	for (const std::string & instruction : assembler_code)
	{
		assembler += instruction + "\n";
	}
	
	return this->sethook(operation, address, assembler, nop_count, retain_bytes);
}

bool zephyrus::assemble(const std::string & assembler_code, std::vector<uint8_t>& bytecode)
{
#ifdef KEYSTONE_ASSEMBLER
	return assembler(std::vector<std::string>(), 
#ifdef X64
		assembler::x64
#else
		assembler::x86
#endif
	).bytecodes(reinterpret_cast<uint64_t>(bytecode.data()), assembler_code, bytecode);
#else

	throw "assembler not defined, failed at zephyrus::assemble";

	return false;
#endif
}

size_t zephyrus::getnopcount(address_t address, hook_operation operation)
{
#if defined(CAPSTONE_DISASSEMBLER) || defined(ZYDIS_DISASSEMBLER)
	size_t hooksize = 5 + (operation > 0xff ? 1 : 0);

	std::vector<std::vector<uint8_t>> instructions = disassembler(static_cast<uint64_t>(address), 
#ifdef X86
			this->readmemory(address, 12)
#elif X64
			this->readmemory(address, 32), disassembler::x64
#endif
	).get_instructions_bytecode();

	for (size_t n = 0, m = 0; n < instructions.size(); ++n)
	{
		if (instructions.at(n).size() + m < hooksize)
		{
			m += instructions.at(n).size();
		}
		else
		{
			return instructions.at(n).size() + m - hooksize;
		}
	}

#else

	throw "disassembler not defined, failed at zephyrus::getnopcount";

#endif

	return static_cast<size_t>(-1);
}

const std::string zephyrus::byte_to_string(const std::vector<uint8_t>& bytes, const std::string & separator)
{
	std::stringstream stream;
	for (size_t n = 0; n < bytes.size(); ++n)
	{
		if (!separator.compare("\\x"))
		{
			stream << separator << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));
		}
		else
		{
			stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));

			if (bytes.size() - 1 != n)
			{
				stream << separator;
			}
		}
	}

	return stream.str();
}

const std::vector<uint8_t> zephyrus::string_to_bytes(const std::string & array_of_bytes)
{
	std::string aob(array_of_bytes);
	std::vector<uint8_t> bytes;

	aob.erase(std::remove(aob.begin(), aob.end(), ' '), aob.end());
	if (aob.empty() || aob.size() % 2)
	{
		return bytes;
	}

	bytes.reserve(aob.size() / 2);

	std::mt19937 mt(static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count()));
	std::uniform_int_distribution<int16_t> dist(0, 15);
	std::stringstream stream;

	for (auto it = aob.begin(); it != aob.end(); ++it)
	{
		if (!isxdigit(*it))
		{
			stream << std::hex << std::setw(1) << dist(mt);
		}
		else
		{
			stream << std::hex << std::setw(1) << *it;
		}

		if (stream.str().size() == 2)
		{
			bytes.push_back(std::stoi(stream.str(), 0, 16));
			stream.str("");
		}
	}

	return bytes;
}

address_t zephyrus::getexportedfunctionaddress(const std::string & module_name, const std::string & function_name)
{
	HMODULE module = GetModuleHandleA(module_name.c_str());
	if (!module)
	{
		module = LoadLibraryA(module_name.c_str());
		if (!module)
		{
			return 0;
		}
	}

	return reinterpret_cast<address_t>(GetProcAddress(module, function_name.c_str()));
}
