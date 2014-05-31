LOCAL_PATH=.

#phLibNfc

export PKG_CONFIG_PATH=/usr/lib/pkgconfig/

#sources

SRCS = $(LOCAL_PATH)/bt_paring.c
       
#includes

USER_HEADER =`pkg-config --cflags nfc bluetooth-api`
	      
LOCAL_CFLAGS = $(USER_HEADER)

CC = arm-linux-gnueabi-gcc

TARGET = bt_paring


CFLAGS = $(LOCAL_CFLAGS) -g
LDFLAGS = -lpthread `pkg-config --libs nfc bluetooth-api`


SRC = $(SRCS)
OBJS = $(SRC:.c=.o)
RM = rm


.SUFFIXES: .c .o
	
.c.o:
	$(CC) -c $(CFLAGS) -o $*.o $< 

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) -g
	
run: all
	$(TARGET)

clean: 
	$(RM) -f $(OBJS) $(TARGET)

