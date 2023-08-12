
add_executable(test_connection ${CMAKE_CURRENT_LIST_DIR}/test_connection.c)
target_link_libraries(test_connection PRIVATE atclient)
add_test(NAME Connection COMMAND test_connection)