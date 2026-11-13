if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT OR NOT DEFINED SYMBOL)
    message(FATAL_ERROR "Usage: cmake -DINPUT=<file> -DOUTPUT=<header> -DSYMBOL=<name> -P bin2hdr.cmake")
endif()

file(READ "${INPUT}" HEX_DATA HEX)
string(LENGTH "${HEX_DATA}" HEX_LEN)
math(EXPR BYTE_LEN "${HEX_LEN} / 2")
if(BYTE_LEN LESS_EQUAL 0)
    message(FATAL_ERROR "Input binary is empty: ${INPUT}")
endif()

string(REGEX REPLACE "([0-9a-fA-F][0-9a-fA-F])" "0x\\1," C_ARRAY "${HEX_DATA}")

file(WRITE "${OUTPUT}"
"/* Auto-generated from ${INPUT} */\n"
"#pragma once\n"
"#include <stddef.h>\n"
"#include <stdint.h>\n\n"
"static const uint8_t ${SYMBOL}[] = {\n"
"${C_ARRAY}\n"
"};\n"
"static const size_t ${SYMBOL}_len = ${BYTE_LEN}u;\n"
)
