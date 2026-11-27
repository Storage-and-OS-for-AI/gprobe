/* SPDX-License-Identifier: MIT
 *
 * MACA runtime init environment hygiene.
 *
 * mcInit() internally forks `sh -c "command -v zip > /dev/null 2>&1"`
 * (a zip probe). The child inherits the environment — including
 * LD_PRELOAD. When the MACA runtime is initialized from a gprobe
 * LD_PRELOAD library (agent / syscall-server), that probe shell would
 * re-load the library and re-run its constructor: in the agent this
 * deadlocks on the shm flock (the parent holds the lock and waits for
 * the probe, the probe's constructor waits for the lock). This guard
 * temporarily removes LD_PRELOAD (and the gprobe knobs) around every
 * mcInit/mcIpc* call so the runtime's child processes run clean — the
 * same class of fix as the ROCm port's unsetenv-in-fork (#18).
 */
#ifndef _GPROBE_MACA_ENV_GUARD_HPP
#define _GPROBE_MACA_ENV_GUARD_HPP

#include <cstdlib>
#include <string>

namespace gprobe
{
namespace maca
{

class maca_runtime_env_guard {
    public:
	maca_runtime_env_guard()
	{
		saved_ld_preload_ = getenv_safe("LD_PRELOAD");
		saved_log_output_ = getenv_safe("GPROBE_LOG_OUTPUT");
		saved_maca_source_ = getenv_safe("GPROBE_MACA_SOURCE");
		unsetenv("LD_PRELOAD");
		unsetenv("GPROBE_LOG_OUTPUT");
		unsetenv("GPROBE_MACA_SOURCE");
	}
	~maca_runtime_env_guard()
	{
		restore("LD_PRELOAD", saved_ld_preload_);
		restore("GPROBE_LOG_OUTPUT", saved_log_output_);
		restore("GPROBE_MACA_SOURCE", saved_maca_source_);
	}
	maca_runtime_env_guard(const maca_runtime_env_guard &) = delete;
	maca_runtime_env_guard &
	operator=(const maca_runtime_env_guard &) = delete;

    private:
	static std::string getenv_safe(const char *name)
	{
		const char *v = getenv(name);
		return v ? std::string(v) : std::string();
	}
	static void restore(const char *name, const std::string &value)
	{
		if (!value.empty())
			setenv(name, value.c_str(), 1);
	}

	std::string saved_ld_preload_;
	std::string saved_log_output_;
	std::string saved_maca_source_;
};

} // namespace maca
} // namespace gprobe

#endif
