from tools.command_handler import CommandHandler
class DesktopMbedTLSCommandHandler(CommandHandler):
  def __init__(self, root_dir):
    super().__init__('desktop', 'mbedtls', root_dir)
    pass
  def handle(self, command, args):
    return super().handle(command, args)
  def init(self, args):
    from sys import executable
    from subprocess import check_call
    exit_code = check_call([executable, '-m', 'pip', 'install', 'cmake==3.25.2'])
    if exit_code != 0:
      print('Unable to automatically install cmake. Please install it manually:')
      print('python -m pip install cmake==3.25.2')
    pass
  def build(self, args):
    super().build(args)
    from subprocess import check_call
    # Run cmake
    exit_code = check_call([
      'cmake',
      '-S', self.root_dir,
      '-B', self.root_dir+'/build/'+self.dir_name,
      '-D', 'BUILD_MBEDTLS=ON',
      ])
    if exit_code != 0:
      super()._build_fail(args)
      return
    # Run make
    exit_code = check_call(['make', '-C', self.root_dir+'/build/'+self.dir_name, 'all'])
    if exit_code != 0:
      super()._build_fail(args)
      return
    # Create lib directory
    from os import makedirs
    makedirs(self.root_dir+'/lib/'+self.dir_name, exist_ok=True)
    # Copy libraries to lib directory
    from glob import glob
    from shutil import copy
    for lib in glob(self.root_dir+'/build/'+self.dir_name+'/lib*.a'):
      copy(lib, self.root_dir+'/lib/'+self.dir_name+'/')
    super()._build_copy(args)
    print('Build successful!')
    pass
  def clean(self, args):
    return super().clean(args)
  def project(self, args):
    project_path, project_name = super().project(args)
    print('Created project '+project_name)
    pass