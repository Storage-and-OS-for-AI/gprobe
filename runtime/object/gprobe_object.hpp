#ifndef _GPROBE_BPF_OBJECT_H_
#define _GPROBE_BPF_OBJECT_H_

#include "gprobe_config.hpp"
namespace gprobe
{

// ebpf object file
class gprobe_object;
// open the object elf file and load it into the context
gprobe_object *gprobe_object_open(const char *obj_path);
gprobe_object *gprobe_object_open(const char *obj_path, runtime_config cfg);
// load btf associate with the host environment
int gprobe_object_load_relocate_btf(gprobe_object *obj, const char *btf_path);
// close and free the object
void gprobe_object_close(gprobe_object *obj);

// The execution unit or bpf function.
class gprobe_prog;
// find the program by section name
gprobe_prog *gprobe_object_find_program_by_name(gprobe_object *obj,
						  const char *name);
gprobe_prog *gprobe_object_find_program_by_secname(gprobe_object *obj,
						     const char *secname);
gprobe_prog *gprobe_object__next_program(const gprobe_object *obj,
					   gprobe_prog *prog);

#define gprobe_object__for_each_program(pos, obj)                             \
	for ((pos) = gprobe_object__next_program((obj), NULL); (pos) != NULL; \
	     (pos) = gprobe_object__next_program((obj), (pos)))

} // namespace gprobe

#endif // _GPROBE_BPF_OBJECT_H_
