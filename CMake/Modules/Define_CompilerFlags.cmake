# Here should go compiler specific flags and stuff.

# This project uses C++11.
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# Debug has -D_DEBUG
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG -g")

# Release
SET(CMAKE_CXX_FLAGS_RELEASE "-O2")
