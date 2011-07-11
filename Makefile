OUT=lazyfs promise
CXX=g++ -g -Wall
all: $(OUT)

lazyfs: lazyfs.cpp
	$(CXX) -o $@ $+

promise: promise.cpp
	$(CXX) -o $@ $+

clean:
	rm -f $(OUT) *~
