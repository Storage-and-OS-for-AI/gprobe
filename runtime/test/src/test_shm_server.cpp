/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <fcntl.h>
#include <unistd.h>
#include <frida-gum.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>
#include <inttypes.h>
#include <dlfcn.h>
#include "gprobe.hpp"
#include "gprobe_shm.hpp"
#include "gprobe_handler.hpp"

using namespace gprobe;
using namespace boost::interprocess;

int main(int argc, const char **argv)
{
	gprobe_initialize_global_shm(shm_open_type::SHM_REMOVE_AND_CREATE);
	gprobe::bpf_map_attr attr;
	attr.type = bpf_map_type::BPF_MAP_TYPE_HASH;
	gprobe_maps_create(-1, "test", attr);
	return system(
		(std::string("./test_shm_client_Tests") + " sub").c_str());
}
