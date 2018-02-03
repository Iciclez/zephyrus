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

#include "aobscan.hpp"


aobscan::aobscan(const std::string & pattern, void *memory_start, size_t memory_size, int32_t result)
	: aobscanbase(pattern, memory_start, memory_size, result)
{
}

aobscan::~aobscan() noexcept
{
}
