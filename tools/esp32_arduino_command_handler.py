from tools.command_handler import CommandHandler
class ESP32ArduinoCommandHandler(CommandHandler):
  def __init__(self, root_dir):
    super().__init__('esp32', 'arduino', root_dir)
    from sys import path as python_path
    idf_dir = root_dir+'/deps/arduino-esp32'
    python_path.append(idf_dir+'/tools')
    pass
  def handle(self, command, args):
    return super().handle(command, args)
  def init(self, args):

    pass
  def build(self, args):
    super().build(args)
    from subprocess import check_call
    exit_code = check_call(['platformio', 'run', '--environment', 'esp32_arduino'])
    if exit_code == 0:
      super()._build_fail(args)
      return
    super()._build_copy(args)
    print('Build successful!')
    pass
  def clean(self, args):
    return super().clean(args)
  def project(self, args):
    project_path, project_name = super().project(args)
    print('Created project '+project_name)
    pass
