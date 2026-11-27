/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifndef GPROBE_DAEMON_HPP
#define GPROBE_DAEMON_HPP

#include "daemon_config.hpp"

namespace gprobe
{
int start_daemon(struct daemon_config env);
} // namespace gprobe

#endif // GPROBE_DAEMON_HPP