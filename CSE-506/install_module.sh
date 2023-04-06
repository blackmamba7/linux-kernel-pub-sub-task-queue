#!/bin/sh
ASYNC_OPS_MODULE_PATH=/lib/modules/$(uname -r)/build/CSE-506
# lsmod
rmmod async_ops_module
insmod $ASYNC_OPS_MODULE_PATH/async_ops_module.ko
# lsmod