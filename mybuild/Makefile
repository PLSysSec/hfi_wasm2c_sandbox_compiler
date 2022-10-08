.PHONY: build build-debug clean

PARALLEL_COUNT=$(shell nproc)

../build_debug_nonhfi:
	CFLAGS=-DWASM2C_HFI_DISABLED CXXFLAGS=-DWASM2C_HFI_DISABLED cmake -S ../ -B ../build_debug_nonhfi -DCMAKE_BUILD_TYPE=Debug

../build_debug_hfi:
	CFLAGS=-DWASM2C_HFI_ENABLED CXXFLAGS=-DWASM2C_HFI_ENABLED cmake -S ../ -B ../build_debug_hfi -DCMAKE_BUILD_TYPE=Debug

../build_release_nonhfi:
	CFLAGS=-DWASM2C_HFI_DISABLED CXXFLAGS=-DWASM2C_HFI_DISABLED cmake -S ../ -B ../build_release_nonhfi -DCMAKE_BUILD_TYPE=Release

../build_release_hfi:
	CFLAGS=-DWASM2C_HFI_ENABLED CXXFLAGS=-DWASM2C_HFI_ENABLED cmake -S ../ -B ../build_release_hfi -DCMAKE_BUILD_TYPE=Release

build: ../build_release_nonhfi ../build_release_hfi
	cd ../build_release_nonhfi && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfi && make -j$(PARALLEL_COUNT)

build-debug: ../build_debug_nonhfi ../build_debug_hfi
	cd ../build_debug_nonhfi && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfi && make -j$(PARALLEL_COUNT)

clean:
	rm -rf ../build_debug_nonhfi
	rm -rf ../build_debug_hfi
	rm -rf ../build_release_nonhfi
	rm -rf ../build_release_hfi
