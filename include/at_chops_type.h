#pragma once

#include "dart_type.h"

namespace AtChopsType
{
  typedef struct InitialisationVector
  {
    size_t ivLen;
    DartType::Uint8List iv;
  } InitialisationVector;
}
