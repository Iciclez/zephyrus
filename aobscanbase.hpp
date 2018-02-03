/*

Copyright 2018 Iciclez

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once
#include <windows.h>
#include <string>
#include <vector>

class aobscanbase
{
public:
	aobscanbase(const std::string &pattern, void *memory_start = 0, size_t memory_size = 0, uint32_t result = 1);
	~aobscanbase() noexcept;

	const std::vector<byte> &get_bytearray();
	const std::vector<byte> &get_mask();
	const std::string &get_pattern();

protected:
	std::vector<byte> bytearray;
	std::vector<byte> mask;
	std::string pattern;

	void *memory_start;
	size_t memory_size;
	uint32_t result;
	size_t pattern_size;
};

