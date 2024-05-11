# at_talk

## Description

at_talk is a simple demo of using notify/monitor for two atSigns to talk to each other end-to-end encrypted.

## Quick Start

Open two terminals. Replace `@bob` and `@alice` with your atSigns. It is assumed that each of the terminals has read access to the existing .atKeys files that are found in `~/.atsign/keys/`.

On terminal 1:

```sh
./run.sh -f @bob -t @alice
```

On terminal 2;

```sh
./run.sh -f @alice -t @bob
```

## Demo

Here's an example of two atSigns talking to each other. In this case, I have keys to `@soccer0` and `@soccer99`. My atKeys were placed in `~/.atsign/keys/` (so my key files were ~/.atsign/keys/@soccer_0_key.atKeys and ~/.atsign/keys/@soccer_99_key.atKeys).

Terminal 1:

```
$ ./run.sh -f @soccer0 -t @soccer99
Setup (1/3) .. (2/3) .. (3/3).
@soccer0 -> Here's an example of at_talk in action.
@soccer0 -> 
@soccer99: Cool isn't it?
```

Terminal 2:

```
$ ./run.sh -f @soccer99 -t @soccer0
Setup (1/3) .. (2/3) .. (3/3).
@soccer99 -> 
@soccer0: Here's an example of at_talk in action.
Cool isn't it?
@soccer99 -> 
```