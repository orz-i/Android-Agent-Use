cmake_minimum_required(VERSION 3.22.1)
project(aau_ebpf LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(BPF_ARCH_MACRO "__TARGET_ARCH_arm64")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(BPF_ARCH_MACRO "__TARGET_ARCH_arm")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(BPF_ARCH_MACRO "__TARGET_ARCH_x86_64")
elseif(ANDROID_ABI STREQUAL "x86")
    set(BPF_ARCH_MACRO "__TARGET_ARCH_x86")
else()
    message(FATAL_ERROR "Unsupported ANDROID_ABI for AAU eBPF probe: ${ANDROID_ABI}")
endif()

set(BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/aau_ebpf.bpf.c")
set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/aau_ebpf.bpf.o")
set(BPF_HDR "${CMAKE_CURRENT_BINARY_DIR}/aau_ebpf_bpf_blob.h")
set(BIN2HDR_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/bin2hdr.cmake")

add_custom_command(
    OUTPUT "${BPF_OBJ}"
    COMMAND "${CMAKE_C_COMPILER}"
        --target=bpf
        -O2
        -g
        -Wall
        -Wextra
        -nostdinc
        -fno-stack-protector
        "-D${BPF_ARCH_MACRO}"
        -c "${BPF_SRC}"
        -o "${BPF_OBJ}"
    DEPENDS "${BPF_SRC}"
    COMMENT "Compiling eBPF bytecode (${BPF_ARCH_MACRO}) -> ${BPF_OBJ}"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BPF_HDR}"
    COMMAND "${CMAKE_COMMAND}"
        "-DINPUT=${BPF_OBJ}"
        "-DOUTPUT=${BPF_HDR}"
        "-DSYMBOL=g_aau_ebpf_bpf_o"
        -P "${BIN2HDR_SCRIPT}"
    DEPENDS "${BPF_OBJ}" "${BIN2HDR_SCRIPT}"
    COMMENT "Embedding eBPF object -> ${BPF_HDR}"
    VERBATIM
)

add_executable(aau_ebpf
    "${CMAKE_CURRENT_SOURCE_DIR}/aau_ebpf_loader.c"
    "${BPF_HDR}"
)

target_include_directories(aau_ebpf PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options(aau_ebpf PRIVATE -O2 -Wall -Wextra)

# Package executable inside jniLibs/<abi>/libaau_ebpf.so so Android extracts it with +x to nativeLibraryDir.
set_target_properties(aau_ebpf PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
)
