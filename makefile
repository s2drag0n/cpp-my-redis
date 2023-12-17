total:
	g++ -g server-mac.cpp -o server -std=c++11 && g++ -g client.cpp -o client -std=c++11

clean:
	rm client server
