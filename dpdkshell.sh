#!/bin/bash

DEVICE="ens34"
DRIVER="igb_uio"
DEVNUM="0000:02:02.0"

while getopts ":hd:r:" optname
do
  case "$optname" in
    "h")
      echo "   `basename ${0}`:usage:[-d device_name] [-r driver_name]"
      echo "   where device_name can be one in: {ens33,ens34},driver_name can be one in: {igb_uio,rte_kni}"
      exit 1
      ;;
    "d")
      DEVICE=$OPTARG
      ;;
    "r")
      DRIVER=$OPTARG
      ;;
    *)
    # Should not occur
      echo "Unknown error while processing options"
      ;;
  esac
done

mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
ifconfig $DEVICE down
modprobe uio
insmod build/kmod/$DRIVER.ko
./usertools/dpdk-devbind.py --bind=$DRIVER $DEVNUM
