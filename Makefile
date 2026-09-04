NAME = traceroute
CC = clang

CFLAGS = -std=c17 \
         -Wall \
         -Wextra \
         -Wpedantic \
		 -Werror
		 
SAN = -fsanitize=address,undefined \
	  -fno-sanitize-recover=undefined -g -O1

traceroute: main.c
	$(CC) $(CFLAGS) main.c -o $(NAME)

san: main.c
	$(CC) $(CFLAGS) $(SAN) main.c -o $(NAME)

clean:
	rm -f $(NAME)