from command_handler import CommandHandler
class ESP32ESPIDFCommandHandler(CommandHandler):
  def __init__(self):
    super().__init__('esp32', 'espidf', 'esp32/espidf')
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
    from os import makedirs, getenv
    if getenv('IDF_PATH') is None:
      print('IDF_PATH not set. Please run "esp32.py init" first.')
      exit(1)
    from idf import init_cli, PROG, SHELL_COMPLETE_VAR
    makedirs(self.root_dir+'/lib/esp32', exist_ok=True)
    idf_cli = init_cli()
    build_args =['-B', 'build/esp32', '-G', 'Unix Makefiles', 'build','-D', 'BUILD_ESP_IDF=ON']
    idf_cli(build_args, prog_name=PROG, complete_var=SHELL_COMPLETE_VAR)
    pass
  def clean(self, args):
    return super().clean(args)
  def project(self, args):
    project_path, project_name = super().project(args)
    with open(project_path+'/CMakeLists.txt', 'r') as f:
      data = f.read()
    data = data.replace('esp32_archetype', project_name)
    with open(project_path+'/CMakeLists.txt', 'w') as f:
      f.write(data)
    print('Created project '+project_name)
    pass
