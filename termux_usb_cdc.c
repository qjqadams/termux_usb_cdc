/*
 * This is a simple example to communicate with a CDC-ACM USB device
 * using libusb.
 *
 * Author: Christophe Augier <christophe.augier@gmail.com>
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <libusb-1.0/libusb.h>

/* You may want to change the VENDOR_ID and PRODUCT_ID
 * depending on your device.
 */
#define VENDOR_ID      0x1915   // Arduino LLC
#define PRODUCT_ID     0x521f   // Arduino Leonardo

#define ACM_CTRL_DTR   0x01
#define ACM_CTRL_RTS   0x02

/* We use a global variable to keep the device handle
 */
static struct libusb_device_handle *devh = NULL;

/* The Endpoint address are hard coded. You should use lsusb -v to find
 * the values corresponding to your device.
 */
static int ep_in_addr  = 0x81;
static int ep_out_addr = 0x01;

int write_data(unsigned char *data, int size) 
{
    int actual_length;
    int rc = libusb_bulk_transfer(devh, ep_out_addr, data, size, &actual_length, 0);
    if (rc < 0) {
        fprintf(stderr, "write_data Error %d errno=%s\n", rc, strerror(errno));
    }
    else {
        fprintf(stderr, "write_data ok rc=%d actual_length=%d\n", rc, actual_length);
    }
    return actual_length;
}

int read_chars(unsigned char *data, int size) {
    int actual_length;
    int rc = libusb_bulk_transfer(devh, ep_in_addr, data, size, &actual_length, 1000);
    if (rc == LIBUSB_ERROR_TIMEOUT) {
        //printf("timeout (%d)\n", actual_length);
        return -1;
    } else if (rc < 0) {
        fprintf(stderr, "Error while waiting for char\n");
        return -1;
    }

    return actual_length;
}

int main(int argc, char **argv) {
    libusb_context *context;
    libusb_device_handle *handle;
    libusb_device *device;
    struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *usb_cfg_desc;
    unsigned char buffer[256];
    int fd;
	int rc;
    assert((argc > 1) && (sscanf(argv[1], "%d", &fd) == 1));
    libusb_set_option(NULL, LIBUSB_OPTION_WEAK_AUTHORITY);
    assert(!libusb_init(&context));
    assert(!libusb_wrap_sys_device(context, (intptr_t) fd, &handle));
    device = libusb_get_device(handle);
    assert(!libusb_get_device_descriptor(device, &desc));
    printf("Vendor ID: %04x\n", desc.idVendor);
    printf("Product ID: %04x\n", desc.idProduct);
    printf("Product ID: %04x\n", desc.idProduct);
    assert(libusb_get_string_descriptor_ascii(handle, desc.iManufacturer, buffer, 256) >= 0);
    printf("Manufacturer: %s\n", buffer);
    assert(libusb_get_string_descriptor_ascii(handle, desc.iProduct, buffer, 256) >= 0);
    printf("Product: %s\n", buffer);
    if (libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, buffer, 256) >= 0) {
        printf("Serial No: %s\n", buffer);
	}

	printf("|--[Vid:0x%04x, Pid:0x%04x]-[Class:0x%02x, SubClass:0x%02x]-[bus:%d, device:%d, port:%d]-[cfg_desc_num:%d]\n",
        desc.idVendor, desc.idProduct, desc.bDeviceClass, desc.bDeviceSubClass,
	    libusb_get_bus_number(device), libusb_get_device_address(device), libusb_get_port_number(device), desc.bNumConfigurations);
	for(int i=0; i < desc.bNumConfigurations; i++) {
		rc = libusb_get_config_descriptor(device, i, &usb_cfg_desc);
		if(rc > 0) {
        	printf("libusb_get_config_descriptor(cfg_index:%d)  err with %d", i, rc);
            goto out;
    	}
		printf("|  |--cfg_desc:%02d-[cfg_value:0x%01x]-[infc_desc_num:%02d]\n",
                i, usb_cfg_desc->bConfigurationValue, usb_cfg_desc->bNumInterfaces);
		for(int j=0; j<usb_cfg_desc->bNumInterfaces; j++) {
			for(uint8_t n = 0;n < usb_cfg_desc->interface[j].num_altsetting; n++) {
                printf("|  |  |--intfc_desc: %02d:%02d-[Class:0x%02x, SubClass:0x%02x]-[ep_desc_num:%02d]\n",
                    j, n, usb_cfg_desc->interface[j].altsetting[n].bInterfaceClass, usb_cfg_desc->interface[j].altsetting[n].bInterfaceSubClass,
                    usb_cfg_desc->interface[j].altsetting[n].bNumEndpoints);
                 for(uint8_t m = 0;m < usb_cfg_desc->interface[j].altsetting[n].bNumEndpoints; m++)
                 {
                    printf("|  |  |  |--ep_desc:%02d-[Add:0x%02x]-[Attr:0x%02x]-[MaxPkgLen:%02d]\n",
                        m, usb_cfg_desc->interface[j].altsetting[n].endpoint[m].bEndpointAddress,
                        usb_cfg_desc->interface[j].altsetting[n].endpoint[m].bmAttributes,
                        usb_cfg_desc->interface[j].altsetting[n].endpoint[m].wMaxPacketSize);
                 }
            }
		}

	}
    devh = handle;

    /* As we are dealing with a CDC-ACM device, it's highly probable that
     * Linux already attached the cdc-acm driver to this device.
     * We need to detach the drivers from all the USB interfaces. The CDC-ACM
     * Class defines two interfaces: the Control interface and the
     * Data interface.
     */
    for (int if_num = 0; if_num < 2; if_num++) {
        if (libusb_kernel_driver_active(devh, if_num)) {
            libusb_detach_kernel_driver(devh, if_num);
        }
        rc = libusb_claim_interface(devh, if_num);
		//rc = libusb_set_interface_alt_setting(devh, if_num, 0);
        if (rc < 0) {
            fprintf(stderr, "Error claiming interface: %s\n",
                    libusb_error_name(rc));
            goto out;
        }
    }
	//err = libusb_clear_halt(msd->msd_handle, msd->endpoint_in);
    //if(err > 0)
    //{
//        LOG_ERROR("[0x%04x:0x%04x] ep_in:%x clear halt failed err with %d", VID, PID, msd->endpoint_in, (int8_t)err);
//        goto epclrhalt_err;
//    }
/*
	rc = libusb_set_interface_alt_setting(devh, 0, 0);
	if(rc != 0) {
		fprintf(stderr, "Error cannot configure alternate setting.\n");
  		goto out;
	}
	rc = libusb_set_interface_alt_setting(devh, 2, 0);
	if(rc != 0) {
		fprintf(stderr, "Error cannot configure alternate setting.\n");
  		goto out;
	}
*/
    /* Start configuring the device:
     * - set line state
     */
    rc = libusb_control_transfer(devh, 0x21, 0x22, ACM_CTRL_DTR | ACM_CTRL_RTS, 0, NULL, 0, 0);
    if (rc < 0) {
        fprintf(stderr, "Error during control transfer: %s\n", libusb_error_name(rc));
    }

    /* - set line encoding: here 9600 8N1
     * 9600 = 0x2580 ~> 0x80, 0x25 in little endian
     * 115200 = 0x01C2 ~> 0xC2, 0x01 in little endian
     */
    // for USBCDC : 9600bps : 0x8025
    unsigned char encoding[] = { 0x80, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08 };

    rc = libusb_control_transfer(devh, 0x21, 0x20, 0, 0, encoding, sizeof(encoding), 0);
    if (rc < 0) {
        fprintf(stderr, "Error during control transfer2: %s\n", libusb_error_name(rc));
    }

    /* We can now start sending or receiving data to the device
     */
    // unsigned char buf[1024];
    // int len;
    
    while (1) {
        sleep(1);
        uint8_t data[4] = {0x01, 0x03, 0x0C, 0x00};
        write_data(data, sizeof(data));
        // len = read_chars(buf, 1024);
        // buf[len] = 0;
        // fprintf(stdout, "%s", buf);
        // sleep(1);
    }

    libusb_release_interface(devh, 0);

out:
    if (devh)
            libusb_close(devh);
    libusb_exit(NULL);
    return rc;
}
