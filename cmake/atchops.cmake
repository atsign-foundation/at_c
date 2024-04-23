if(NOT TARGET atchops)
  message(
    STATUS
    "[ATCHOPS] package not found, fetching from local repository.."
  )
  fetchcontent_declare(atchops SOURCE_DIR ${atchops_DIR})
  fetchcontent_makeavailable(atchops)
  install(TARGETS atchops)
endif()
