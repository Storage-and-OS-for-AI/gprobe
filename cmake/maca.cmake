function(find_maca)
    if(NOT GPROBE_MACA_ROOT)
        message(FATAL_ERROR "To use MACA attach, set GPROBE_MACA_ROOT to the root of MACA installation, such as /opt/maca/")
    endif()

    set(MACA_LIBRARY_PATH ${GPROBE_MACA_ROOT}/lib PARENT_SCOPE)
    set(MACA_INCLUDE_PATH ${GPROBE_MACA_ROOT}/include/mcr PARENT_SCOPE)
    set(MACA_INCLUDE_PATH_EXTRA ${GPROBE_MACA_ROOT}/include PARENT_SCOPE)

    # NO_DEFAULT_PATH: force looking inside the MACA SDK only, so a
    # system-wide stale installation cannot shadow the SDK runtime
    # (the same class of bug as the ROCm libamdhip64.so.5/.so.7 one).
    find_library(MCRUNTIME_LIB NAMES mcruntime
        HINTS ${GPROBE_MACA_ROOT}/lib
        NO_DEFAULT_PATH REQUIRED)

    set(MACA_LIBS ${MCRUNTIME_LIB} PARENT_SCOPE)
    set(MACA_HELPER_PATH attach/maca_attach_impl/trampoline/default_trampoline.maca PARENT_SCOPE)
endfunction()
