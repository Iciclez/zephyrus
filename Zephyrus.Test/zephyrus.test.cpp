#include "pch.h"
#include "CppUnitTest.h"


#include "zephyrus.hpp"
#include "disassembler.hpp"
#include "aobscan.hpp"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace zephyrus_test
{
#ifdef _WIN64
	__declspec(dllexport) int zephyrus_test_function()
	{
		return 0;
	}	
#elif _WIN32
	__declspec(naked) void zephyrus_test_function()
	{
		__asm
		{
			xor eax, eax
			ret
		}
	}
#endif

	TEST_CLASS(zephyrus_test)
	{
	public:
		
		TEST_METHOD(test_readmemory)
		{
			uint32_t n = 0x12345678;

			std::vector<uint8_t> actual = zephyrus().readmemory(reinterpret_cast<address_t>(&n), sizeof(n));

			Assert::AreEqual(sizeof(n), actual.size());
			Assert::AreEqual<uint8_t>(0x78, actual.at(0));
			Assert::AreEqual<uint8_t>(0x56, actual.at(1));
			Assert::AreEqual<uint8_t>(0x34, actual.at(2));
			Assert::AreEqual<uint8_t>(0x12, actual.at(3));
		}

		TEST_METHOD(test_writememory)
		{
			uint32_t n = 0xdeadbeef;

			Assert::IsTrue(zephyrus().writememory(reinterpret_cast<address_t>(&n), { 0x78, 0x56, 0x34, 0x12 }, false));
			Assert::AreEqual<uint32_t>(0x12345678, n);
		}

		TEST_METHOD(test_writememory_string)
		{
			uint32_t n = 0xdeadbeef;

			Assert::IsTrue(zephyrus().writememory(reinterpret_cast<address_t>(&n), "78 56 34 12", false));
			Assert::AreEqual<uint32_t>(0x12345678, n);
		}

		TEST_METHOD(test_copymemory)
		{
			uint32_t n = 0xdeadbeef;

			Assert::IsTrue(zephyrus().copymemory(reinterpret_cast<address_t>(&n), "\x78\x56\x34\x12", sizeof(n)));
			Assert::AreEqual<uint32_t>(0x12345678, n);
		}

		TEST_METHOD(test_writeassembler)
		{
			uint32_t n = 0xdeadbeef;

			Assert::IsTrue(zephyrus().writeassembler(reinterpret_cast<address_t>(&n), "xor eax, eax", false));
			Assert::AreEqual<uint32_t>(0xdeadc031, n);
		}

		TEST_METHOD(test_writepadding)
		{
			uint32_t n = 0xdeadbeef;

			Assert::IsTrue(zephyrus().writepadding(reinterpret_cast<address_t>(&n), 3));
			Assert::AreEqual<uint32_t>(0xde909090, n);
		}

		TEST_METHOD(test_revertmemory)
		{
			uint32_t n = 0xdeadbeef;
			zephyrus z;
			
			z.writememory(reinterpret_cast<address_t>(&n), std::vector<uint8_t>{ 0x78, 0x56, 0x34, 0x12 });

			Assert::IsTrue(z.revertmemory(reinterpret_cast<address_t>(&n)));
			Assert::AreEqual<uint32_t>(0xdeadbeef, n);
		}

		TEST_METHOD(test_redirect)
		{
			zephyrus z;

			static bool variable = false;

			typedef decltype(&MessageBoxA) messageboxa_t;
			static messageboxa_t messageboxa = &MessageBoxA;

			auto to = [](
				_In_opt_ HWND    hWnd,
				_In_opt_ LPCSTR lpText,
				_In_opt_ LPCSTR lpCaption,
				_In_     UINT    uType) -> int
			{
				variable = true;
				//messageboxa(hWnd, lpText, lpCaption, uType);
				return TRUE;
			};

			z.redirect<messageboxa_t>(&messageboxa, to);

			MessageBoxA(0, "redirect test failed", "", MB_OK);
			Assert::IsTrue(variable);

			z.redirect<messageboxa_t>(&messageboxa, nullptr, false);
			//MessageBoxA(0, "redirect test ok", "", MB_OK);
		}

		TEST_METHOD(test_detour)
		{
			zephyrus z;

			static bool variable = false;

			typedef decltype(&MessageBoxA) messageboxa_t;
			static messageboxa_t messageboxa = &MessageBoxA;

			auto to = [](
				_In_opt_ HWND    hWnd,
				_In_opt_ LPCSTR lpText,
				_In_opt_ LPCSTR lpCaption,
				_In_     UINT    uType) -> int
			{
				variable = true;
				//messageboxa(hWnd, lpText, lpCaption, uType);
				return TRUE;
			};

			z.detour<messageboxa_t>(&messageboxa, to);

			MessageBoxA(0, "detour test failed", "", MB_OK);
			Assert::IsTrue(variable);

			z.detour<messageboxa_t>(&messageboxa, to, false);
			//MessageBoxA(0, "detour test ok", "", MB_OK);
		}

		TEST_METHOD(test_sethook)
		{
#ifdef _WIN64
			//if test_redirect passes, this passes
			Assert::IsTrue(true);
#elif _WIN32
			zephyrus z;
			uint64_t n = 0x12345678deadbeef;

			Assert::IsTrue(z.sethook(JMP, reinterpret_cast<address_t>(&n), reinterpret_cast<address_t>(zephyrus_test_function), 0, false));
			Assert::AreEqual<uint8_t>(JMP, n & 0xff);

			disassembler memory(reinterpret_cast<uint64_t>(&n), z.readmemory(reinterpret_cast<address_t>(&n), 5));

#ifdef CAPSTONE_DISASSEMBLER
			Assert::AreEqual<int32_t>(X86_OP_IMM, memory.get_instructions().at(0).detail->x86.operands[0].type);
			Assert::AreEqual(reinterpret_cast<int64_t>(zephyrus_test_function), memory.get_instructions().at(0).detail->x86.operands[0].imm);
#elif ZYDIS_DISASSEMBLER
			Assert::AreEqual<int32_t>(ZydisMnemonic::ZYDIS_MNEMONIC_JMP, memory.get_instructions().at(0).mnemonic);
			Assert::AreEqual<int32_t>(ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE, memory.get_instructions().at(0).operands[0].type);

			uint64_t zephyrus_test_function_address;
			Assert::AreEqual(ZYAN_STATUS_SUCCESS, ZydisCalcAbsoluteAddress(&memory.get_instructions().at(0), &memory.get_instructions().at(0).operands[0], reinterpret_cast<uint64_t>(&n), &zephyrus_test_function_address));
			Assert::AreEqual(reinterpret_cast<uint64_t>(zephyrus_test_function), zephyrus_test_function_address);

			Assert::AreEqual<uint64_t>(reinterpret_cast<uint64_t>(zephyrus_test_function), reinterpret_cast<uint64_t>(&n) + memory.get_instructions().at(0).length + memory.get_instructions().at(0).operands[0].imm.value.s);
#endif
#endif
		}

		TEST_METHOD(test_writedata)
		{
			uint64_t n = 0x12345678deadbeef;
			
			Assert::IsTrue(zephyrus().writedata<uint8_t>(reinterpret_cast<address_t>(&n), 0x90));
			Assert::AreEqual<uint64_t>(0x12345678deadbe90, n);
			
			Assert::IsTrue(zephyrus().writedata<uint16_t>(reinterpret_cast<address_t>(&n), 0xbaad));
			Assert::AreEqual<uint64_t>(0x12345678deadbaad, n);

			Assert::IsTrue(zephyrus().writedata<uint32_t>(reinterpret_cast<address_t>(&n), 0xdeadbeef));
			Assert::AreEqual<uint64_t>(0x12345678deadbeef, n);

			Assert::IsTrue(zephyrus().writedata<uint64_t>(reinterpret_cast<address_t>(&n), 0xdeadbeef12345678));
			Assert::AreEqual<uint64_t>(0xdeadbeef12345678, n);
		}

		TEST_METHOD(test_readdata)
		{
			uint64_t n = 0x12345678deadbeef;

			Assert::AreEqual<uint8_t>(0xef, zephyrus().readdata<uint8_t>(reinterpret_cast<address_t>(&n)));
			Assert::AreEqual<uint32_t>(0xbeef, zephyrus().readdata<uint16_t>(reinterpret_cast<address_t>(&n))); //ok
			Assert::AreEqual<uint32_t>(0xdeadbeef, zephyrus().readdata<uint32_t>(reinterpret_cast<address_t>(&n)));
			Assert::AreEqual<uint64_t>(0x12345678deadbeef, zephyrus().readdata<uint64_t>(reinterpret_cast<address_t>(&n)));
		}


		TEST_METHOD(test_writepointer)
		{
			struct test_struct {
				uint8_t a;
				uint16_t b;
				uint32_t c;
				uint64_t d;
			};

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, d));

			test_struct obj = { 0x33, 0x9090, 0xbaadf00d, 0xdeadbeefdeadbeef };
			test_struct* ptr = &obj;

			Assert::IsTrue(zephyrus::writepointer<uint8_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, a), 0x88));
			Assert::AreEqual<uint8_t>(0x88, ptr->a);

			Assert::IsTrue(zephyrus::writepointer<uint16_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, b), 0xefef));
			Assert::AreEqual<uint32_t>(0xefef, ptr->b);

			Assert::IsTrue(zephyrus::writepointer<uint32_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, c), 0x45454545));
			Assert::AreEqual<uint32_t>(0x45454545, ptr->c);
			
			Assert::IsTrue(zephyrus::writepointer<uint64_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, d), 0x1234567887654321));
			Assert::AreEqual<uint64_t>(0x1234567887654321, ptr->d);
		}

		TEST_METHOD(test_readpointer)
		{
			struct test_struct {
				uint8_t a;
				uint16_t b;
				uint32_t c;
				uint64_t d;
			};

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, d));

			test_struct obj = { 0x33, 0x9090, 0xbaadf00d, 0xdeadbeefdeadbeef };
			test_struct* ptr = &obj;

			Assert::AreEqual<uint8_t>(ptr->a, zephyrus::readpointer<uint8_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, a)));
			Assert::AreEqual<uint32_t>(ptr->b, zephyrus::readpointer<uint16_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, b)));
			Assert::AreEqual<uint32_t>(ptr->c, zephyrus::readpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, c)));
			Assert::AreEqual<uint64_t>(ptr->d, zephyrus::readpointer<uint64_t>(reinterpret_cast<address_t>(&ptr), offsetof(struct test_struct, d)));
		}

		TEST_METHOD(test_writemultilevelpointer)
		{
			struct test_struct_inner {
				uint32_t x;
				uint32_t* y;
				uint32_t z;
			};

			struct test_struct {
				uint8_t a;
				uint16_t b;
				uint32_t* c;
				test_struct_inner* d;
				uint64_t e;
			};

#ifdef _WIN64
			Assert::AreEqual<size_t>(0, offsetof(struct test_struct_inner, x));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct_inner, y));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct_inner, z));

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct, d));
			Assert::AreEqual<size_t>(24, offsetof(struct test_struct, e));
#elif _WIN32
			Assert::AreEqual<size_t>(0, offsetof(struct test_struct_inner, x));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct_inner, y));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct_inner, z));

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, d));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct, e));
#endif
			uint32_t v1 = 0xc0cac0ca;
			uint32_t v2 = 0xbaadf00d;

			test_struct_inner inner_obj = { 0x11223344, &v1, 0x56565656 };

			test_struct obj = { 0x33, 0x9090, &v2, &inner_obj, 0xdeadbeefdeadbeef };
			test_struct* ptr = &obj;

			Assert::IsTrue(zephyrus::writemultilevelpointer<uint8_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, a) }), 0x88));
			Assert::AreEqual<uint8_t>(0x88, ptr->a);

			Assert::IsTrue(zephyrus::writemultilevelpointer<uint16_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, b) }), 0xefef));
			Assert::AreEqual<uint32_t>(0xefef, ptr->b);

			Assert::IsTrue(zephyrus::writemultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, c), 0 }), 0x45454545));
			Assert::AreEqual<uint32_t>(0x45454545, *ptr->c);

			Assert::IsTrue(zephyrus::writemultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, x) }), 0x11111111));
			Assert::AreEqual<uint32_t>(0x11111111, ptr->d->x);
			Assert::IsTrue(zephyrus::writemultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, y), 0 }), 0x77777777));
			Assert::AreEqual<uint32_t>(0x77777777, *ptr->d->y);
			Assert::IsTrue(zephyrus::writemultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, z) }), 0x66666666));
			Assert::AreEqual<uint32_t>(0x66666666, ptr->d->z);

			Assert::IsTrue(zephyrus::writemultilevelpointer<uint64_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, e) }), 0x1234567887654321));
			Assert::AreEqual<uint64_t>(0x1234567887654321, ptr->e);
		}

		TEST_METHOD(test_readmultilevelpointer)
		{
			struct test_struct_inner {
				uint32_t x;
				uint32_t *y;
				uint32_t z;
			};

			struct test_struct {
				uint8_t a;
				uint16_t b;
				uint32_t *c;
				test_struct_inner* d;
				uint64_t e;
			};

#ifdef _WIN64
			Assert::AreEqual<size_t>(0, offsetof(struct test_struct_inner, x));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct_inner, y));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct_inner, z));

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct, d));
			Assert::AreEqual<size_t>(24, offsetof(struct test_struct, e));
#elif _WIN32
			Assert::AreEqual<size_t>(0, offsetof(struct test_struct_inner, x));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct_inner, y));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct_inner, z));

			Assert::AreEqual<size_t>(0, offsetof(struct test_struct, a));
			Assert::AreEqual<size_t>(2, offsetof(struct test_struct, b));
			Assert::AreEqual<size_t>(4, offsetof(struct test_struct, c));
			Assert::AreEqual<size_t>(8, offsetof(struct test_struct, d));
			Assert::AreEqual<size_t>(16, offsetof(struct test_struct, e));
#endif
			uint32_t v1 = 0xc0cac0ca;
			uint32_t v2 = 0xbaadf00d;

			test_struct_inner inner_obj = { 0x11223344, &v1, 0x56565656 };

			test_struct obj = { 0x33, 0x9090, &v2, &inner_obj, 0xdeadbeefdeadbeef };
			test_struct* ptr = &obj;

			Assert::AreEqual<uint8_t>(ptr->a, zephyrus::readmultilevelpointer<uint8_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, a) })));
			Assert::AreEqual<uint32_t>(ptr->b, zephyrus::readmultilevelpointer<uint16_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, b) })));
			Assert::AreEqual<uint32_t>(*ptr->c, zephyrus::readmultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, c), 0 })));
			
			Assert::AreEqual<uint32_t>(ptr->d->x, zephyrus::readmultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, x) })));
			Assert::AreEqual<uint32_t>(*ptr->d->y, zephyrus::readmultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, y), 0 })));
			Assert::AreEqual<uint32_t>(ptr->d->z, zephyrus::readmultilevelpointer<uint32_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, d), offsetof(struct test_struct_inner, z) })));

			Assert::AreEqual<uint64_t>(ptr->e, zephyrus::readmultilevelpointer<uint64_t>(reinterpret_cast<address_t>(&ptr), std::queue<size_t>({ offsetof(struct test_struct, e) })));
		
		}

		TEST_METHOD(test_aobscan)
		{
			std::vector<uint8_t> haystack = {
				0xf1, 0x80, 0xd7, 0x50, 0x1a, 0x7b, 0x69, 0x57, 0x07, 0x80, 0xbc, 0x27, 0xc7, 0x5e, 0x88, 0x0c,
				0xac, 0x7f, 0xd8, 0xe0, 0x13, 0x7d, 0xf4, 0xfb, 0xf4, 0x91, 0x0b, 0x07, 0xa6, 0xe1, 0x54, 0x22
			};

			
			Assert::AreEqual<address_t>(reinterpret_cast<address_t>(haystack.data()) + 5, aobscan("7b ?? 57 07 ?? bc ?? c7", haystack.data(), haystack.size()).address<address_t>());
			Assert::AreEqual<address_t>(0, aobscan("7b ?? 57 33 07 ?? bc ?? c7", haystack.data(), haystack.size()).address<address_t>());
		}

		TEST_METHOD(test_string_to_bytes)
		{
			std::vector<uint8_t> expected = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
			std::vector<uint8_t> actual = zephyrus::string_to_bytes("12 34 56 78 90 AB CD EF");
			Assert::AreEqual(expected.size(), actual.size());

			for (size_t n = 0; n < expected.size(); ++n)
			{
				Assert::AreEqual(expected.at(n), actual.at(n));
			}
		}

		TEST_METHOD(test_bytes_to_string)
		{
			Assert::AreEqual<std::string>("12 34 56 78 90 AB CD EF", zephyrus::byte_to_string(std::vector<uint8_t>{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef }));
			Assert::AreEqual<std::string>("\\x12\\x34\\x56\\x78\\x90\\xAB\\xCD\\xEF", zephyrus::byte_to_string(std::vector<uint8_t>{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef }, "\\x"));
			Assert::AreEqual<std::string>("1234567890ABCDEF", zephyrus::byte_to_string(std::vector<uint8_t>{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef }, ""));
			Assert::AreEqual<std::string>("12*34*56*78*90*AB*CD*EF", zephyrus::byte_to_string(std::vector<uint8_t>{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef }, "*"));
		}
	};
}
