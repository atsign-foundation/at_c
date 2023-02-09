#!/usr/bin/env python

from argparse import ArgumentParser
from os import path

root_dir = path.dirname(path.realpath(__file__))

### Platform Options ###
available_platforms = ['desktop', 'esp32']

available_frameworks = {
  'desktop': ['mbedtls'],
  'esp32': ['espidf', 'arduino']
}

base_commands = ['init', 'build', 'clean', 'project']

available_commands = {
  'desktop': {
    'mbedtls': base_commands,
  },
  'esp32': {
    'espidf': base_commands, # + ['flash', 'monitor']
    'arduino': base_commands, # + ['flash', 'monitor']
  },
}

### Argument Parsing ###

class ArgNamespace(object): pass

def get_platform_parser(parser, namespace):
  parser.add_argument('-p','--platform', choices=available_platforms, default='desktop')
  parser.parse_known_args(namespace=namespace)
  return parser, namespace

def get_framework_parser(parser, namespace):
  choices = available_frameworks[namespace.platform]
  parser.add_argument('-f','--framework', choices=choices, default=choices[0])
  parser.parse_known_args(namespace=namespace)
  return parser, namespace

def get_command_parser(parser, namespace):
  choices = available_commands[namespace.platform][namespace.framework]
  parser.add_argument('command', choices=choices)
  parser.parse_known_args(namespace=namespace)
  return parser, namespace

def get_additional_args(parser, namespace):
  if namespace.command == 'project':
    parser.add_argument('project_path', help='Path to output directory')
  parser.parse_args(namespace=namespace)
  return parser, namespace

def parse_args():
  parser = ArgumentParser(conflict_handler='resolve')
  namespace = ArgNamespace()
  parser, namespace = get_platform_parser(parser, namespace)
  parser, namespace = get_framework_parser(parser, namespace)
  parser, namespace = get_command_parser(parser, namespace)
  parser, namespace = get_additional_args(parser, namespace)
  return namespace.platform, namespace.framework, namespace.command, namespace

def main():
  platform, framework, command, args = parse_args()
  if platform == 'desktop':
    if framework == 'mbedtls':
      from tools import DesktopMbedTLSCommandHandler
      handler = DesktopMbedTLSCommandHandler()
    else: raise Exception('Unknown framework: ' + framework)
  elif platform == 'esp32':
    if framework == 'espidf':
      from tools import ESP32ESPIDFCommandHandler
      handler = ESP32ESPIDFCommandHandler()
    elif framework == 'arduino':
      from tools import ESP32ArduinoCommandHandler
      handler = ESP32ArduinoCommandHandler()
    else: raise Exception('Unknown framework: ' + framework)
  else: raise Exception('Unknown platform: ' + platform)
  handler.handle(command, args)


if __name__ == '__main__':
  main()
