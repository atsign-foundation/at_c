# Just

Just is a command runner with a similar file format to make.

There are 3 relevant files in the root of the repo:

  1. [justfile](../justfile)
  2. [just.template.env](../just.template.env)
  3. [just.env](../just.env)

The `just.env` file should be created by making a copy of the `just.template.env`
file. Then values in just.env can be configured locally.

## Usage

### Project maintenance

Setup the project for development:

`just setup`

Clean the build cache:

`just clean`

### Building the project

Build in debug mode:

`just build`

Build in release mode:

`just build-release`

### Testing

Run all tests:

`just test`

Run only unit or functional tests:

`just unit` or `just func`

Test commands pass arguments to ctest, so you can pass a regex like so:

`just test '-R monitor'`

> This will only run tests which contain `monitor` in the name.

#### Running memcheck

Locally (requires valgrind):

`just memcheck`

In docker, first run the setup to build the docker image locally:

`just setup-memcheck-docker`

Then whenever you want to run the memory check tests:

`just memd`

> This will create an ephemeral docker container, all of the test output will be located in `build/test-memcheck/` as if it was run locally.

### See all commands

Run `just --list` or look through the contents of the [justfile](../justfile)
