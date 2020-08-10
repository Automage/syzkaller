// AUTOGENERATED FILE

package build

const createImageScript = `#!/bin/bash


set -eux

CLEANUP=""
trap 'eval " $CLEANUP"' EXIT

IMG_ARCH="${3:-amd64}"

if [ ! -e $1/sbin/init ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage [arch]"
	exit 1
fi

case "$IMG_ARCH" in
	386|amd64)
		KERNEL_IMAGE_BASENAME=bzImage
		;;
	ppc64le)
		KERNEL_IMAGE_BASENAME=zImage.pseries
		;;
esac

if [ "$(basename $2)" != "$KERNEL_IMAGE_BASENAME" ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage [arch]"
	exit 1
fi

SYZ_VM_TYPE="${SYZ_VM_TYPE:-qemu}"
if [ "$SYZ_VM_TYPE" == "qemu" ]; then
	:
elif [ "$SYZ_VM_TYPE" == "gce" ]; then
	:
else
	echo "SYZ_VM_TYPE has unsupported value $SYZ_VM_TYPE"
	exit 1
fi

BLOCK_DEVICE="loop"
if [ "$(uname -a | grep Ubuntu)" != "" ]; then
	BLOCK_DEVICE="nbd"
fi

sudo umount disk.mnt || true
if [ "$BLOCK_DEVICE" == "loop" ]; then
	:
elif [ "$BLOCK_DEVICE" == "nbd" ]; then
	sudo modprobe nbd
	sudo qemu-nbd -d /dev/nbd0 || true
fi
rm -rf disk.mnt disk.raw || true

fallocate -l 2G disk.raw
if [ "$BLOCK_DEVICE" == "loop" ]; then
	DISKDEV="$(sudo losetup -f --show -P disk.raw)"
	CLEANUP="sudo losetup -d $DISKDEV; $CLEANUP"
elif [ "$BLOCK_DEVICE" == "nbd" ]; then
	DISKDEV="/dev/nbd0"
	sudo qemu-nbd -c $DISKDEV --format=raw disk.raw
	CLEANUP="sudo qemu-nbd -d $DISKDEV; $CLEANUP"
fi

case "$IMG_ARCH" in
	386|amd64)
		echo -en "o\nn\np\n1\n\n\na\nw\n" | sudo fdisk $DISKDEV
		PARTDEV=$DISKDEV"p1"
		;;
	ppc64le)
		echo -en "g\nn\n1\n2048\n16383\nt\n7\nn\n2\n\n\nw\n" | sudo fdisk $DISKDEV
		PARTDEV=$DISKDEV"p2"
		;;
esac

until [ -e $PARTDEV ]; do sleep 1; done
sudo -E mkfs.ext4 -O ^resize_inode,^has_journal,ext_attr,extents,huge_file,flex_bg,dir_nlink,sparse_super $PARTDEV
mkdir -p disk.mnt
CLEANUP="rm -rf disk.mnt; $CLEANUP"
sudo mount $PARTDEV disk.mnt
CLEANUP="sudo umount disk.mnt; $CLEANUP"
sudo cp -a $1/. disk.mnt/.
sudo cp $2 disk.mnt/vmlinuz
sudo sed -i "/^root/ { s/:x:/::/ }" disk.mnt/etc/passwd
echo "T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100" | sudo tee -a disk.mnt/etc/inittab
echo -en "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n" | sudo tee disk.mnt/etc/network/interfaces
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo "securityfs /sys/kernel/security securityfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo "configfs /sys/kernel/config/ configfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a disk.mnt/etc/fstab
for i in {0..31}; do
	echo "KERNEL==\"binder$i\", NAME=\"binder$i\", MODE=\"0666\"" | \
		sudo tee -a disk.mnt/etc/udev/50-binder.rules
done

echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | sudo tee -a disk.mnt/etc/udev/rules.d/50-udev-default.rules

echo "kernel.printk = 7 4 1 3" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "debug.exception-trace = 0" | sudo tee -a disk.mnt/etc/sysctl.conf
SYZ_SYSCTL_FILE="${SYZ_SYSCTL_FILE:-}"
if [ "$SYZ_SYSCTL_FILE" != "" ]; then
	cat $SYZ_SYSCTL_FILE | sudo tee -a disk.mnt/etc/sysctl.conf
fi

echo -en "127.0.0.1\tlocalhost\n" | sudo tee disk.mnt/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a disk.mnt/etc/resolve.conf
echo "ClientAliveInterval 420" | sudo tee -a disk.mnt/etc/ssh/sshd_config
echo "syzkaller" | sudo tee disk.mnt/etc/hostname
rm -f key key.pub
ssh-keygen -f key -t rsa -N ""
sudo mkdir -p disk.mnt/root/.ssh
sudo cp key.pub disk.mnt/root/.ssh/authorized_keys
sudo chown root disk.mnt/root/.ssh/authorized_keys
sudo mkdir -p disk.mnt/boot/grub

CMDLINE=""
SYZ_CMDLINE_FILE="${SYZ_CMDLINE_FILE:-}"
if [ "$SYZ_CMDLINE_FILE" != "" ]; then
	CMDLINE=$(awk '{printf("%s ", $0)}' $SYZ_CMDLINE_FILE)
fi

case "$IMG_ARCH" in
386|amd64)
	cat << EOF | sudo tee disk.mnt/boot/grub/grub.cfg
terminal_input console
terminal_output console
set timeout=0
menuentry 'linux' --class gnu-linux --class gnu --class os {
	insmod vbe
	insmod vga
	insmod video_bochs
	insmod video_cirrus
	insmod gzio
	insmod part_msdos
	insmod ext2
	set root='(hd0,1)'
	linux /vmlinuz root=/dev/sda1 console=ttyS0 earlyprintk=serial vsyscall=native rodata=n oops=panic panic_on_warn=1 nmi_watchdog=panic panic=86400 net.ifnames=0 sysctl.kernel.hung_task_all_cpu_backtrace=1 $CMDLINE
}
EOF
	sudo grub-install --target=i386-pc --boot-directory=disk.mnt/boot --no-floppy $DISKDEV
	;;
ppc64le)
	cat << EOF | sudo tee disk.mnt/boot/grub/grub.cfg
terminal_input console
terminal_output console
set timeout=0
menuentry 'linux' --class gnu-linux --class gnu --class os {
	insmod gzio
	insmod part_gpt
	insmod ext2
	set root='(ieee1275/disk,gpt2)'
	linux /vmlinuz root=/dev/sda2 console=ttyS0 earlyprintk=serial rodata=n oops=panic panic_on_warn=1 nmi_watchdog=panic panic=86400 net.ifnames=0 $CMDLINE
}
EOF
	sudo grub-install --target=powerpc-ieee1275 --boot-directory=disk.mnt/boot $DISKDEV"p1"
	;;
esac
`
