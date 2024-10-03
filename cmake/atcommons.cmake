if(NOT TARGET atcommons)
  include(FetchContent)
  message(
    STATUS
    "[ATCOMMONS] package not found, fetching from local repository.. [PATH: ${atcommons_DIR}]"
  )
  FetchContent_Declare(atcommons SOURCE_DIR ${atcommons_DIR})
  FetchContent_MakeAvailable(atcommons)
  install(TARGETS atcommons)
endif()
