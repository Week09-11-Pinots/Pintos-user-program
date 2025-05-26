#!/bin/bash

if [ $# -ne 1 ]; then
  make -j
else
  mv Make.vars Make.vars.old
  cp Make.vars.flag Make.vars
  make -j
  rm Make.vars
  mv Make.vars.old Make.vars
fi 