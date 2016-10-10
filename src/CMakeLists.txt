file(GLOB_RECURSE Sources ../ *.c)

INCLUDE(Define_CMakeDefaults)
INCLUDE(Define_PlatformDefaults)
INCLUDE(Define_CompilerFlags)

ADD_EXECUTABLE(
    ${EXECUTABLE_NAME}
    ${Sources}
)

TARGET_LINK_LIBRARIES(
    ${EXECUTABLE_NAME} elf gpgme gpg-error
)



