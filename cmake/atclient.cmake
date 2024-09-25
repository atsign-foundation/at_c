if(NOT TARGET atclient)
  include(FetchContent)
  message(
    STATUS
    "[ATCLIENT] package not found, fetching from local repository.."
  )
  FetchContent_Declare(atclient SOURCE_DIR ${atclient_DIR})
  FetchContent_MakeAvailable(atclient)
  install(TARGETS atclient)
endif()
