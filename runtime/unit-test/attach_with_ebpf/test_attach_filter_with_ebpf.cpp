#include "gprobe_config.hpp"
#include "gprobe_shm_internal.hpp"
#include <catch2/catch_test_macros.hpp>
#include "helper.hpp"
#include <spdlog/spdlog.h>
#include <unit-test/common_def.hpp>
#include <frida_uprobe_attach_impl.hpp>
using namespace gprobe;

// This is the original function to hook.
extern "C" __attribute__((__noinline__)) int
__gprobe_attach_filter_with_ebpf__my_function(const char *str, char c,
					       long long parm1)
{
	asm("");
	// buggy code: not check str is NULL
	int i = str[0];
	SPDLOG_INFO("origin func: Args: {}, {}, {}", str, c, i);
	return (int)parm1;
}

extern "C" uint64_t __gprobe_attach_filter_with_ebpf__test_pass_param(
	uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t, uint64_t)
{
	char *str = (char *)arg1;
	char c = (char)arg2;
	long long param1 = (long long)arg3;
	// "hello aaa", 'c', 182
	REQUIRE(strcmp(str, "hello aaa") == 0);
	REQUIRE(c == 'c');
	REQUIRE(param1 == 182);
	return 0;
}

static const char *ebpf_prog_path = TOSTRING(EBPF_PROGRAM_PATH_FILTER);

TEST_CASE("Test attaching filter program with ebpf, and reverting")
{
	gprobe::runtime_config config;
	config.set_vm_name("llvm");
	REQUIRE(__gprobe_attach_filter_with_ebpf__my_function("hello aaa", 'c',
							       182) == 182);
	std::unique_ptr<gprobe_object, decltype(&gprobe_object_close)> obj(
		gprobe_object_open(ebpf_prog_path, std::move(config)),
		gprobe_object_close);
	REQUIRE(obj.get() != nullptr);
	attach::frida_attach_impl man;
	auto prog = gprobe_object__next_program(obj.get(), nullptr);
	REQUIRE(prog != nullptr);
	REQUIRE(gprobe_helper_group::get_ufunc_helper_group()
			.add_helper_group_to_prog(prog) >= 0);
	REQUIRE(gprobe_helper_group::get_kernel_utils_helper_group()
			.add_helper_group_to_prog(prog) >= 0);
	gprobe_helper_info info = {
		.index = 40,
		.name = "test_pass_param",
		.fn = (void *)__gprobe_attach_filter_with_ebpf__test_pass_param,
	};
	REQUIRE(prog->gprobe_prog_register_raw_helper(info) >= 0);
	REQUIRE(prog->gprobe_prog_load(false) >= 0);
	int id = man.create_uprobe_override_at(
		(void *)__gprobe_attach_filter_with_ebpf__my_function,
		[=](const pt_regs &regs) {
			uint64_t ret;
			REQUIRE(prog->gprobe_prog_exec((void *)&regs,
							sizeof(regs),
							&ret) >= 0);
		});
	REQUIRE(id >= 0);
	REQUIRE(__gprobe_attach_filter_with_ebpf__my_function("hello aaa", 'c',
							       182) == 182);
	REQUIRE(__gprobe_attach_filter_with_ebpf__my_function(nullptr, 'c',
							       1) == -22);
	SECTION("Destroy with id")
	{
		REQUIRE(man.detach_by_id(id) >= 0);
	}
	SECTION("Destroy with address")
	{
		REQUIRE(man.detach_by_func_addr((
				void *)__gprobe_attach_filter_with_ebpf__my_function) >=
			0);
	}
	REQUIRE(__gprobe_attach_filter_with_ebpf__my_function("hello aaa", 'c',
							       182) == 182);
}
