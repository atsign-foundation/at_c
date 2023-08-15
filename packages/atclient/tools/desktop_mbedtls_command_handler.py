from command_handler import CommandHandler
class DesktopMbedTLSCommandHandler(CommandHandler):
  def __init__(self, root_dir):
    super().__init__('desktop', 'mbedtls', root_dir)
    pass
  def handle(self, command, args):
    return super().handle(command, args)
  def init(self, args):
    from sys import executable
    from subprocess import check_call
    exit_code = check_call([executable, '-m', 'pip', 'install', 'cmake'])
    if exit_code != 0:
      print('Unable to automatically install cmake. Please install it manually:')
      print('python -m pip install cmake')
    pass
  def build(self, args):
    super().build(args)
    from subprocess import check_call
    # Run cmake
    exit_code = check_call([
      'cmake',
      '-S', self.root_dir,
      '-B', self.build_dir,
      '-D', 'BUILD_MBEDTLS=ON',
      ])
    if exit_code != 0:
      super()._build_fail(args)
      return
    # Run make
    exit_code = check_call(['make', '--directory', self.build_dir, 'all'])
    if exit_code != 0:
      super()._build_fail(args)
      return
    # Create directories
    from os import makedirs
    makedirs(self.build_dir+'/lib/', exist_ok=True)
    makedirs(self.build_dir+'/test/', exist_ok=True)
    # Copy libraries to lib directory and tests to test directory
    from glob import glob
    from shutil import copy
    for lib in glob(self.build_dir+'/lib*.a'):
      copy(lib, self.build_dir+'/lib/')
    for test in glob(self.build_dir+'/test_*'):
      copy(test, self.build_dir+'/test/')
    for lib in glob(self.build_dir+'/deps/mbedtls/library/lib*.a'):
      copy(lib, self.build_dir+'/lib/')
    if args.output is not None:
      from os import path
      output_dir = path.relpath(args.output)
      makedirs(output_dir, exist_ok=True)
      for lib in glob(self.build_dir+'/lib/*'):
        copy(lib, output_dir)
    print('Build successful!')
    pass
  def clean(self, args):
    from shutil import rmtree
    rmtree(self.build_dir, ignore_errors=True)
    print('Done cleaning: ' + self.build_dir)
    pass
  def project(self, args):
    project_path, project_name = super().project(args)
    print('Created project '+project_name)
    pass
  def test(self, args):
    print('Not implemented')
    pass
