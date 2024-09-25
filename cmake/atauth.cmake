if(NOT TARGET atauth)
    include(FetchContent)
    message(
            STATUS
            "[ATAUTH] package not found, fetching from local repository.."
    )
    FetchContent_Declare(atauth SOURCE_DIR ${atauth_DIR})
    FetchContent_MakeAvailable(atauth)
    install(TARGETS atauth)
endif()