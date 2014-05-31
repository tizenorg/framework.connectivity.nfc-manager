LOCAL_PATH=.

#phLibNfc

export PKG_CONFIG_PATH=/usr/lib/pkgconfig/

#sources

SRCS = $(LOCAL_PATH)/main.c
       
#includes

USER_HEADER =`pkg-config --cflags nfc glib-2.0 gobject-2.0`

LOCAL_CFLAGS = $(USER_HEADER)

CC = arm-linux-gnueabi-gcc

TARGET = nfc-test


CFLAGS = $(LOCAL_CFLAGS) -g
LDFLAGS = -lpthread `pkg-config --libs nfc glib-2.0 gobject-2.0`


SRC = $(SRCS)
OBJS = $(SRC:.c=.o)
RM = rm


.SUFFIXES: .c .o
	
.c.o:
	$(CC) -c $(CFLAGS) -o $*.o $< 

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	
run: all
	$(TARGET)

clean: 
	$(RM) -f $(OBJS) $(TARGET)

