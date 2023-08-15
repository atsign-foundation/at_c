from command_handler import CommandHandler

class ESP32ESPIDFCommandHandler(CommandHandler):
  def __init__(self, root_dir):
    super().__init__('esp32', 'espidf', root_dir)
    from sys import path as python_path
    idf_dir = root_dir+'/deps/esp-idf'
    python_path.append(idf_dir+'/tools')
    pass
  def handle(self, command, args):
    return super().handle(command, args)
  def init(self, args):
    import idf_tools
    idf_tools.main(['install'])
    idf_tools.main(['install-python-env'])
    from platform import system
    print('\nPlease run the following command to complete setup:')
    if system() == 'Windows':
      print('call '+self.root_dir+'/tools/init-espidf.bat')
    else:
      print('. '+self.root_dir+'/tools/init-espidf.sh')
    pass
  def build(self, args):
    super().build(args)
    from os import getenv
    if getenv('IDF_PATH') is None:
      print('IDF_PATH not set. Please run "./tool.py -p esp32 -f espidf init" first.')
      exit(1)
    from subprocess import check_call
    # Run cmake
    exit_code = check_call([
      'cmake',
      '-S', self.root_dir,
      '-B', self.root_dir+'/build/'+self.dir_name,
      '-D', 'BUILD_ESP_IDF=ON',
      ])
    if exit_code != 0:
      super()._build_fail(args)
      return
    # Run make
    exit_code = check_call(['make', '-C', self.root_dir+'/build/'+self.dir_name, 'all'])
    if exit_code != 0:
      super()._build_fail(args)
      return
    self._build_copy(args)
    print('Build successful!')
    pass
  def clean(self, args):
    return super().clean(args)
  def project(self, args):
    project_path, project_name = super().project(args)
    with open(project_path+'/CMakeLists.txt', 'r') as f:
      data = f.read()
    data = data.replace('<project-name>', project_name)
    with open(project_path+'/CMakeLists.txt', 'w') as f:
      f.write(data)
    print('Created project '+project_name)
    pass
