from tools.command_handler import CommandHandler
class ESP32ArduinoCommandHandler(CommandHandler):
  def __init__(self, root_dir):
    super().__init__('esp32', 'arduino', root_dir)
    pass
  def handle(self, command, args):
    return super().handle(command, args)
  def init(self, args):
    from sys import executable
    from subprocess import check_call
    exit_code = check_call([executable, '-m', 'pip', 'install', 'platformio==6.1.6'])
    if exit_code != 0:
      print('Unable to automatically install platformio. Please install it manually:')
      print('python -m pip install platformio==6.1.6')
    pass
  def build(self, args):
    pass
  def clean(self, args):
    return super().clean(args)
  def project(self, args):
    project_path, project_name = super().project(args)
    print('Created project '+project_name)
    pass
