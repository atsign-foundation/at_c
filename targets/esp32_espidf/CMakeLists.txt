idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  # All components & dependencies to be built:
  REQUIRES at_client mbedtls
)
