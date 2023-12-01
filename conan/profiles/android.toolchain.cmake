# We don't need to export any symbol implicitly, and also disable C++ exceptions, and enable unwind tables.
set(CMAKE_C_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} -fvisibility=hidden -fno-exceptions -funwind-tables")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS_INIT} -fvisibility=hidden -fno-exceptions -funwind-tables")
