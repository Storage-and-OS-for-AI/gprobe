/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
// test register raw function and call it from ufunc
#include "gprobe_object.hpp"
#include "spdlog/spdlog.h"
#include "unit-test/common_def.hpp"
#include <cstdio>
#include <gprobe_ufunc.hpp>
#include <gprobe_helper_group.hpp>
#include <catch2/catch_test_macros.hpp>
using namespace gprobe;

struct data {
	int a;
	int b;
} __attribute__((__packed__));

extern "C" int _gprobe_test_ufunc_register__add_func(int a, int b)
{
	int res = a + b;
	spdlog::info("helper-add {} = {} + {}", res, a, b);
	return res;
}

extern "C" uint64_t _gprobe_test_ufunc_register__print_func(char *str)
{
	spdlog::info("helper-print: {}", str);
	return 0;
}

static int test_register_ufunc()
{
	struct ebpf_ufunc_func_info func2 = {
		"add_func",
		UFUNC_FN(_gprobe_test_ufunc_register__add_func),
		UFUNC_TYPE_INT32,
		{ UFUNC_TYPE_INT32, UFUNC_TYPE_INT32 },
		2,
		2,
		false
	};
	gprobe_ufunc_register_ufunc(1, func2);

	struct ebpf_ufunc_func_info func1 = {
		"print_func",
		UFUNC_FN(_gprobe_test_ufunc_register__print_func),
		UFUNC_TYPE_INT64,
		{ UFUNC_TYPE_POINTER },
		1,
		2,
		false
	};
	gprobe_ufunc_register_ufunc(2, func1);
	return 0;
}

TEST_CASE("Test ufunc register")
{
	gprobe::runtime_config config;
	config.set_vm_name("llvm");
	const char *obj_path = NULL;
	uint64_t return_val;

	// use a struct as memory
	struct data memory = { 5, 2 };

	obj_path = TOSTRING(EBPF_PROGRAM_PATH_UFUNC);

	test_register_ufunc();

	// open the object file
	gprobe_object *obj = gprobe_object_open(obj_path, std::move(config));
	REQUIRE(obj != nullptr);
	gprobe_prog *prog = gprobe_object__next_program(obj, NULL);
	REQUIRE(prog != nullptr);
	// use the first program and relocate based on btf if btf has been
	// loaded
	int res = gprobe_helper_group::get_ufunc_helper_group()
			  .add_helper_group_to_prog(prog);

	REQUIRE(res == 0);

	// test vm
	res = prog->gprobe_prog_load(false);
	REQUIRE(res == 0);
	return_val = 0;
	res = prog->gprobe_prog_exec(&memory, sizeof(memory), &return_val);
	REQUIRE(return_val == 17);
	prog->gprobe_prog_unload();

	// test jit
	res = prog->gprobe_prog_load(true);
	REQUIRE(res == 0);
	return_val = 0;
	res = prog->gprobe_prog_exec(&memory, sizeof(memory), &return_val);
	REQUIRE(return_val == 17);

	gprobe_object_close(obj);
}
