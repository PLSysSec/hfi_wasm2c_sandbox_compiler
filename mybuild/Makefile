.PHONY: build build-debug clean
.DEFAULT_GOAL := build

PARALLEL_COUNT=$(shell nproc)

../build_debug_guardpages:
	cmake -S ../ -B ../build_debug_guardpages -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_GUARD_PAGES
../build_debug_boundschecks:
	cmake -S ../ -B ../build_debug_boundschecks -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_BOUNDS_CHECKS
../build_debug_masking:
	cmake -S ../ -B ../build_debug_masking -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_MASKING
../build_debug_hfi:
	cmake -S ../ -B ../build_debug_hfi -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI

../build_release_guardpages:
	cmake -S ../ -B ../build_release_guardpages -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_GUARD_PAGES
../build_release_boundschecks:
	cmake -S ../ -B ../build_release_boundschecks -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_BOUNDS_CHECKS
../build_release_masking:
	cmake -S ../ -B ../build_release_masking -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_MASKING
../build_release_hfi:
	cmake -S ../ -B ../build_release_hfi -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI

build: ../build_release_guardpages ../build_release_boundschecks ../build_release_masking ../build_release_hfi
	cd ../build_release_guardpages && make -j$(PARALLEL_COUNT)
	cd ../build_release_boundschecks && make -j$(PARALLEL_COUNT)
	cd ../build_release_masking && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfi && make -j$(PARALLEL_COUNT)

build_debug: ../build_debug_guardpages ../build_debug_boundschecks ../build_debug_masking ../build_debug_hfi
	cd ../build_debug_guardpages && make -j$(PARALLEL_COUNT)
	cd ../build_debug_boundschecks && make -j$(PARALLEL_COUNT)
	cd ../build_debug_masking && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfi && make -j$(PARALLEL_COUNT)

clean:
	rm -rf ../build_debug_*
	rm -rf ../build_release_*
