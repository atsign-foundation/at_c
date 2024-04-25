if(NOT TARGET atclient)
  message(
    STATUS
    "[ATCLIENT] package not found, fetching from local repository.."
  )
  fetchcontent_declare(atclient SOURCE_DIR ${atclient_DIR})
  fetchcontent_makeavailable(atclient)
  install(TARGETS atclient)
endif()
