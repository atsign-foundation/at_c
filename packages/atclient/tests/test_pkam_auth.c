
static int test1_pkam_no_options();
static int test2_pkam_with_options();
// TODO: add apkam enrollment
// - can't do this as a unit test until we have at_activate in C
// static int test3_apkam_enrollment();

int main() {
  int ret = 0;

  ret += test1_pkam_no_options();
  ret += test2_pkam_with_options();

  return ret;
}

static int test1_pkam_no_options() {
  int ret = 0;

  return ret;
}

static int test2_pkam_with_options() {
  int ret = 0;
  return ret;
}
