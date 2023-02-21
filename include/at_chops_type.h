#pragma once

#include <stddef.h>
#include "dart_type.h"

namespace AtChopsType
{
  struct InitialisationVector
  {
    size_t iv_len;
    DartType::Uint8List iv;
  };
}
