#!/bin/bash

if [ $# -eq 0 ]; then
  make -j
elif [ $# -eq 1 ]; then
  if [ "$1" = "wsl" ]; then
    mv Make.vars Make.vars.old
    cp Make.vars.wsl Make.vars
    make -j
    rm Make.vars
    mv Make.vars.old Make.vars
  elif [ "$1" = "debug" ]; then
    mv Make.vars Make.vars.old
    cp Make.vars.debug Make.vars
    make -j
    rm Make.vars
    mv Make.vars.old Make.vars
  else
    echo "Usage: $0 [wsl|debug|wsl debug]"
    exit 1
  fi
elif [ $# -eq 2 ]; then
  if { [ "$1" = "wsl" ] && [ "$2" = "debug" ]; } || { [ "$1" = "debug" ] && [ "$2" = "wsl" ]; }; then
    mv Make.vars Make.vars.old
    cp Make.vars.wsl-debug Make.vars
    make -j
    rm Make.vars
    mv Make.vars.old Make.vars
  else
    echo "Usage: $0 [wsl|debug|wsl debug]"
    exit 1
  fi
else
  echo "Usage: $0 [wsl|debug|wsl debug]"
  exit 1
fi
