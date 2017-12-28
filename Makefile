all:
	go build -o a2b ./atk2bytes
	gcc -o b2a bytes2atk/*.c
	gcc -fPIC -shared -o bytes2atk/b2a.so bytes2atk/*.c
