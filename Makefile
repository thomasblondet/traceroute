CC = cc
CFLAGS = -std=c99 -Wall -Wextra

SRC = traceroute.c
OBJ = $(SRC:.c=.o)

traceroute: $(OBJ)
	$(CC) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f traceroute *.o
