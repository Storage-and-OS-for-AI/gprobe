#include <iostream>
#include "gprobe_shm.hpp"
#include "spdlog/spdlog.h"

int main() {
    gprobe_initialize_global_shm(gprobe::shm_open_type::SHM_CREATE_OR_OPEN);
    const char* jsonFileName = "example_shm.json";
    const char* importJsonName = "ebpf.json";
    SPDLOG_INFO("GLOBAL memory initialized ");
    // load json program to shm
    gprobe_import_global_shm_from_json(importJsonName);
    // export it to another json file
    gprobe_export_global_shm_to_json(jsonFileName);
    // remove content from global shm
    gprobe_remove_global_shm();
    return 0;
}