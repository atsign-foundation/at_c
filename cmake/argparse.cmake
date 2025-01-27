if(NOT TARGET argparse)
  include(FetchContent)
  message(
    STATUS
    "[ARGPARSE] package not found, fetching from local repository.."
  )
  FetchContent_Declare(argparse SOURCE_DIR ${ARGPARSE_DIR})
  FetchContent_MakeAvailable(argparse)
  install(TARGETS argparse)
endif()
