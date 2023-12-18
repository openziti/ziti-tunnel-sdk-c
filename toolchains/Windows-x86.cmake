# cross-compile for windows/arm64 on windows/x64 host with visual studio
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR X86)
#set(CMAKE_GENERATOR_PLATFORM X86)
set(CMAKE_C_COMPILER cl.exe)