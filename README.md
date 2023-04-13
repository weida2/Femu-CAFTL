Description
--------------------------

**This tutorial tells you how to install the FEMU environment and how to run the CAFTL code**


Installation
------------

1. Make sure you have installed necessary libraries for building QEMU. The
   dependencies can be installed by following instructions below:

```bash
git clone https://github.com/weida2/Femu-caftl.git
cd Femu-caftl
mkdir build-femu
# Switch to the FEMU building directory
cd build-femu
# Copy femu script
cp ../femu-scripts/femu-copy-scripts.sh .
./femu-copy-scripts.sh .
# only Debian/Ubuntu based distributions supported
sudo ./pkgdep.sh
```

2. Add parameters to "femu-compile.sh":

```bash
vim femu-compile.sh
  
# copy the code blow

#!/bin/bash
NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"

make clean
# --disable-werror --extra-cflags=-w --disable-git-update
../configure --enable-kvm --target-list=x86_64-softmmu --extra-cflags=-lcrypto
make -j $NRCPUS

echo ""
echo "===> FEMU compilation done ..."
echo ""
```

3. Compile & Install FEMU:

```bash
./femu-compile.sh
```



4. Prepare the VM image (For performance reasons, we suggest to use a server
   version guest OS [e.g. Ubuntu Server 20.04, 18.04, 16.04])

```bash
cd ~
mkdir images
cd images
wget http://people.cs.uchicago.edu/~huaicheng/femu/femu-vm.tar.xz
tar xJvf femu-vm.tar.xz
```

5. You can verify the integrity of the VM image with the following statement

```bash
md5sum u20s.qcow2 > tmp.md5sum
diff tmp.md5sum u20s.md5sum
```



## Run FEMU

1. Configuration size

```bash
vim run-blackbox.sh

# copy the code blow

#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run FEMU as a black-box SSD (FTL managed by the device)

# image directory
IMGDIR=$HOME/images/image2
# Virtual machine disk image
OSIMGF=$IMGDIR/u20s.qcow2

if [[ ! -e "$OSIMGF" ]]; then
        echo ""
        echo "VM disk image couldn't be found ..."
        echo "Please prepare a usable VM image and place it as $OSIMGF"
        echo "Once VM disk image is ready, please rerun this script again"
        echo ""
        exit
fi

sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-BBSSD-VM" \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 12G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device femu,devsz_mb=16384,femu_mode=1 \
    -net user,hostfwd=tcp::8088-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log
```



2. Run FEMU & Log in

```
./run-blackbox.sh
....

fvm login:femu
Password:femu
```

3. If you want to open another window using ssh login.

```bash
usernamexxx@hostnamexxx:~$ ssh -p 8088 femu@localhost
# Password for femu：femu

```



## Run CAFTL Code

1. mkfs & mount 

```bash
mkdir test
sudo mkfs.ext4 /dev/nvme0n1
sudo mount /dev/nvme0n1 test/
```

2. You can use "df - h" to check whether the disk is mounted successfully
3. Write 1G random data into /dev/nvme0n1

```bash
sudo dd if=/dev/urandom of=/dev/nvme0n1 bs=4k count=250000
```

4. You can view the deduplication process in the Log file of the host

```
# Log file path
# In your host not in femu
cd ~/Femu-caftl/build-femu/
cat log
```

