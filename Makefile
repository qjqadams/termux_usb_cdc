
CFLAGS := -O2 -std=c99 -Wall

cdc_example: termux_usb_cdc.o
	$(CC) -o termux_usb_cdc termux_usb_cdc.o -lusb-1.0

default: termux_usb_cdc

clean:
	rm termux_usb_cdc termux_usb_cdc.o
