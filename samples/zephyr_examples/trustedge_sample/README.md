To enable using trustedge with a bootloader, make the following changes.

1. Enable MCUBoot + path to signing key for image
```
CONFIG_BOOTLOADER_MCUBOOT=y
CONFIG_MCUBOOT_SIGNATURE_KEY_FILE="bootloader/mcuboot/root-rsa-2048.pem"
```

2. Update overlay file partitions
update overlay with following flash0:
```
&flash0 {
	partitions {
		compatible = "fixed-partitions";
		#address-cells = <1>;
		#size-cells = <1>;

		boot_partition: partition@0 {
			label = "mcuboot";
			reg = <0x00000000 DT_SIZE_K(128)>;
		};

		slot0_partition: partition@20000 {
			label = "image-0";
			reg = <0x00020000 DT_SIZE_K(896)>;
		};

		slot1_partition: partition@100000 {
			label = "image-1";
			reg = <0x00100000 DT_SIZE_K(896)>;
		};

		scratch_partition: partition@1E0000 {
			label = "scratch";
			reg = <0x001E0000 DT_SIZE_K(128)>;
		};
	};
};
```
