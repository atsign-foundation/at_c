if(NOT TARGET atlogger)
  message(
    STATUS
    "[ATLOGGER] package not found, fetching from local repository.."
  )
  fetchcontent_declare(atlogger SOURCE_DIR ${atlogger_DIR})
  fetchcontent_makeavailable(atlogger)
  install(TARGETS atlogger)
endif()
