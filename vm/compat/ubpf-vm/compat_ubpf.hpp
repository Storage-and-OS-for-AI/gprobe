#ifndef GPROBE_UBPF_COMPACT_H
#define GPROBE_UBPF_COMPACT_H

#include <gprobe_vm_compat.hpp>
#include <map>
#include <string>

namespace gprobe::vm::ubpf
{
std::unique_ptr<gprobe::vm::compat::gprobe_vm_impl> create_ubpf_vm_instance();

class gprobe_ubpf_vm : public compat::gprobe_vm_impl {
    public:
	gprobe_ubpf_vm();
	~gprobe_ubpf_vm() override;
	gprobe_ubpf_vm(const gprobe_ubpf_vm &) = delete;
	gprobe_ubpf_vm &operator=(const gprobe_ubpf_vm &) = delete;
	std::string get_error_message();
	bool toggle_bounds_check(bool enable);
	void register_error_print_callback(int (*fn)(FILE *, const char *,
						     ...));
	int register_external_function(size_t index, const std::string &name,
				       void *fn);
	int load_code(const void *code, size_t code_len);
	void unload_code();
	int exec(void *mem, size_t mem_len, uint64_t &bpf_return_value);
	std::optional<compat::precompiled_ebpf_function> compile();
	void set_lddw_helpers(uint64_t (*map_by_fd)(uint32_t),
			      uint64_t (*map_by_idx)(uint32_t),
			      uint64_t (*map_val)(uint64_t),
			      uint64_t (*var_addr)(uint32_t),
			      uint64_t (*code_addr)(uint32_t));
	int set_unwind_function_index(size_t idx);
	int set_pointer_secret(uint64_t secret);

    private:
	struct ubpf_vm *ubpf_vm;
	std::string error_string;
	uint64_t (*map_by_fd)(uint32_t) = nullptr;
	uint64_t (*map_by_idx)(uint32_t) = nullptr;
	uint64_t (*map_val)(uint64_t) = nullptr;
	uint64_t (*var_addr)(uint32_t) = nullptr;
	uint64_t (*code_addr)(uint32_t) = nullptr;
	// gprobe helper id -> ubpf helper id
	std::map<size_t, size_t> helper_id_map;
	// Next helper id used by ubpf
	size_t next_helper_id = 1;
};
} // namespace gprobe::vm::ubpf

#endif // GPROBE_UBPF_COMPACT_H
