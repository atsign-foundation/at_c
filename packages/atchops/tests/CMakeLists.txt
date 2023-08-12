
add_executable(test_aes_ctr ${CMAKE_CURRENT_LIST_DIR}/test_aes_ctr.c)
target_link_libraries(test_aes_ctr PRIVATE atchops)
add_test(NAME AES_CTR COMMAND test_aes_ctr)

add_executable(test_base64 ${CMAKE_CURRENT_LIST_DIR}/test_base64.c)
target_link_libraries(test_base64 PRIVATE atchops)
add_test(NAME Base64 COMMAND test_base64)

add_executable(test_rsadecrypt ${CMAKE_CURRENT_LIST_DIR}/test_rsadecrypt.c)
target_link_libraries(test_rsadecrypt PRIVATE atchops)
add_test(NAME RSADecrypt COMMAND test_rsadecrypt)

add_executable(test_rsaencrypt ${CMAKE_CURRENT_LIST_DIR}/test_rsaencrypt.c)
target_link_libraries(test_rsaencrypt PRIVATE atchops)
add_test(NAME RSAEncrypt COMMAND test_rsaencrypt)

add_executable(test_rsaprivatepopulate ${CMAKE_CURRENT_LIST_DIR}/test_rsaprivatepopulate.c)
target_link_libraries(test_rsaprivatepopulate PRIVATE atchops)
add_test(NAME RSAPrivatePopulate COMMAND test_rsaprivatepopulate)

add_executable(test_rsapublicpopulate ${CMAKE_CURRENT_LIST_DIR}/test_rsapublicpopulate.c)
target_link_libraries(test_rsapublicpopulate PRIVATE atchops)
add_test(NAME RSAPublicPopulate COMMAND test_rsapublicpopulate)

add_executable(test_rsasign ${CMAKE_CURRENT_LIST_DIR}/test_rsasign.c)
target_link_libraries(test_rsasign PRIVATE atchops)
add_test(NAME RSASign COMMAND test_rsasign)
