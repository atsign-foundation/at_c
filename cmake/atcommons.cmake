if(NOT TARGET atcommons)
  message(
    STATUS
    "[ATCOMMONS] package not found, fetching from local repository.."
  )
  fetchcontent_declare(atcommons SOURCE_DIR ${atcommons_DIR})
  fetchcontent_makeavailable(atcommons)
  install(TARGETS atcommons)
endif()
