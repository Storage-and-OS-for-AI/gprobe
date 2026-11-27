#if __linux__
#include <linux/bpf.h>
#elif __APPLE__
#include "gprobe_epoll.h"
#endif
#include <string>
#include <list>
#include <memory>
#include <string_view>
#include "gprobe_prog.hpp"
#include <spdlog/spdlog.h>
using namespace std;
using namespace gprobe;
#if __APPLE__
using namespace gprobe_epoll;
#endif

#ifdef GPROBE_BUILD_WITH_LIBBPF
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
}
#endif

namespace gprobe
{

// ebpf object file
class gprobe_object {
    public:
	gprobe_object(std::string_view path);
	gprobe_object(std::string_view path, runtime_config cfg);
	~gprobe_object() = default;
	string obj_path;
	std::unique_ptr<struct bpf_object, decltype(&bpf_object__close)> obj;
	std::unique_ptr<struct btf, decltype(&btf__free)> host_btf;

	std::list<std::unique_ptr<gprobe_prog> > progs;

	void create_programs();
	void create_programs(runtime_config cfg);
	gprobe_prog *find_program_by_name(std::string_view name) const;
	gprobe_prog *find_program_by_secname(std::string_view name) const;
	gprobe_prog *next_program(gprobe_prog *prog) const;
};

gprobe_prog *gprobe_object::next_program(gprobe_prog *prog) const
{
	if (!prog) {
		if (progs.empty()) {
			return nullptr;
		}
		return progs.front().get();
	}
	for (auto it = progs.begin(); it != progs.end(); ++it) {
		if (it->get() == prog) {
			auto next = std::next(it);
			if (next == progs.end()) {
				return nullptr;
			}
			return next->get();
		}
	}
	return nullptr;
}

void gprobe_object::create_programs()
{
	bpf_program *prog;
	bpf_object__for_each_program(prog, obj.get())
	{
		if (!prog) {
			continue;
		}
		SPDLOG_INFO("create_programs: found program {}",
			   bpf_program__name(prog));
		struct ebpf_inst *insns =
			(struct ebpf_inst *)bpf_program__insns(prog);
		size_t cnt = bpf_program__insn_cnt(prog);
		const char *name = bpf_program__name(prog);
		if (!insns || !name) {
			SPDLOG_ERROR("Failed to get insns or name for prog {}",
				     name || "<NULL>");
			continue;
		}
		progs.emplace_back(
			std::make_unique<gprobe_prog>(insns, cnt, name));
	}
}

void gprobe_object::create_programs(runtime_config cfg)
{
	bpf_program *prog;
	bpf_object__for_each_program(prog, obj.get())
	{
		if (!prog) {
			continue;
		}
		struct ebpf_inst *insns =
			(struct ebpf_inst *)bpf_program__insns(prog);
		size_t cnt = bpf_program__insn_cnt(prog);
		const char *name = bpf_program__name(prog);
		if (!insns || !name) {
			SPDLOG_ERROR("Failed to get insns or name for prog {}",
				     name || "<NULL>");
			continue;
		}
		progs.emplace_back(std::make_unique<gprobe_prog>(
			insns, cnt, name, std::move(cfg)));
	}
}

gprobe_prog *
gprobe_object::find_program_by_secname(std::string_view name) const
{
	const char *sec_name;
	struct bpf_program *prog = NULL;
	gprobe_prog *time_prog = progs.front().get();
	// iterate through the gprobe_prog from prog and bpf_program
	bpf_object__for_each_program(prog, obj.get())
	{
		if (!prog) {
			continue;
		}
		sec_name = bpf_program__section_name(prog);
		if (!sec_name)
			continue;
		if (strcmp(sec_name, name.data()) == 0) {
			return time_prog;
		}
		time_prog = next_program(time_prog);
	}
	return NULL;
}

gprobe_prog *gprobe_object::find_program_by_name(std::string_view name) const
{
	const char *sec_name;
	for (auto &p : progs) {
		sec_name = p->prog_name();
		if (sec_name && strcmp(sec_name, name.data()) == 0) {
			return p.get();
		}
	}
	return NULL;
}

gprobe_object::gprobe_object(std::string_view path)
	: obj_path(path), obj(nullptr, bpf_object__close),
	  host_btf(nullptr, btf__free)
{
	bpf_object *obj_ptr = bpf_object__open(obj_path.data());
	if (!obj_ptr) {
		SPDLOG_ERROR("Failed to open object file {}", obj_path);
		return;
	}
	obj.reset(obj_ptr);
	create_programs();
}

gprobe_object::gprobe_object(std::string_view path, runtime_config cfg)
	: obj_path(path), obj(nullptr, bpf_object__close),
	  host_btf(nullptr, btf__free)
{
	bpf_object *obj_ptr = bpf_object__open(obj_path.data());
	if (!obj_ptr) {
		SPDLOG_ERROR("Failed to open object file {}", obj_path);
		return;
	}
	obj.reset(obj_ptr);
	create_programs(std::move(cfg));
}

// open the object elf file and load it into the context
gprobe_object *gprobe_object_open(const char *obj_path)
{
	gprobe_object *obj = new gprobe_object(obj_path);
	return obj;
}

gprobe_object *gprobe_object_open(const char *obj_path, runtime_config cfg)
{
	gprobe_object *obj = new gprobe_object(obj_path, std::move(cfg));
	return obj;
}

// close and free the object
void gprobe_object_close(gprobe_object *obj)
{
	if (!obj) {
		return;
	}
	delete obj;
	return;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	return vfprintf(stderr, format, args);
#pragma clang diagnostic pop
}

// The execution unit or bpf function.
class gprobe_prog;
// find the program by section name
gprobe_prog *gprobe_object_find_program_by_name(gprobe_object *obj,
							const char *name)
{
	if (!obj || !name) {
		return NULL;
	}
	return obj->find_program_by_name(name);
}

gprobe_prog *gprobe_object_find_program_by_secname(gprobe_object *obj,
							   const char *secname)
{
	if (!obj || !secname) {
		return NULL;
	}
	return obj->find_program_by_secname(secname);
}

gprobe_prog *gprobe_object__next_program(const gprobe_object *obj,
						 class gprobe_prog *prog)
{
	if (!obj) {
		return NULL;
	}
	return obj->next_program(prog);
}

} // namespace gprobe
