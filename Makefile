test: 
	gcc -Wall -Wextra analyseur.c -o analyseur  -lpcap

clean : 
	rm analyseur
