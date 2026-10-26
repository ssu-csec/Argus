                                   
 
                                                         
             
 
                                                            

include(CheckIncludeFile)
include(CheckLibraryExists)

if (LLVM_ENABLE_LIBPFM)
  check_library_exists(pfm pfm_initialize "" HAVE_LIBPFM_INITIALIZE)
  if(HAVE_LIBPFM_INITIALIZE)
    check_include_file(perfmon/perf_event.h HAVE_PERFMON_PERF_EVENT_H)
    check_include_file(perfmon/pfmlib.h HAVE_PERFMON_PFMLIB_H)
    check_include_file(perfmon/pfmlib_perf_event.h HAVE_PERFMON_PFMLIB_PERF_EVENT_H)
    if(HAVE_PERFMON_PERF_EVENT_H AND HAVE_PERFMON_PFMLIB_H AND HAVE_PERFMON_PFMLIB_PERF_EVENT_H)
      set(HAVE_LIBPFM 1)
    endif()
  endif()
endif()


