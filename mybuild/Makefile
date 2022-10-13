.PHONY: build build-debug clean
.DEFAULT_GOAL := build

PARALLEL_COUNT=$(shell nproc)

../build_debug_guardpages:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_GUARD_PAGES
../build_debug_boundschecks:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_BOUNDS_CHECKS
../build_debug_masking:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_MASKING
../build_debug_hfi:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI
../build_debug_hfiemulate:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION_ENABLE=ON
../build_debug_hfiemulate_rr:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION_ENABLE=ON -DHFI_EMULATION_RR_ENABLE=ON
../build_debug_hfiemulate2:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION2_ENABLE=ON
../build_debug_hfiemulate2_nouvwasi:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Debug -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION2_ENABLE=ON -DWASM_NO_UVWASI

../build_release_guardpages:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_GUARD_PAGES
../build_release_boundschecks:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_BOUNDS_CHECKS
../build_release_masking:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_MASKING
../build_release_hfi:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI
../build_release_hfiemulate:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION_ENABLE=ON
../build_release_hfiemulate_rr:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION_ENABLE=ON -DHFI_EMULATION_RR_ENABLE=ON
../build_release_hfiemulate2:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION2_ENABLE=ON
../build_release_hfiemulate2_nouvwasi:
	cmake -S ../ -B $@ -DCMAKE_BUILD_TYPE=Release -DWasmSafetyEnforcement=WASM_USE_HFI -DHFI_EMULATION2_ENABLE=ON -DWASM_NO_UVWASI

build: ../build_release_guardpages ../build_release_boundschecks ../build_release_masking ../build_release_hfi ../build_release_hfiemulate ../build_release_hfiemulate_rr ../build_release_hfiemulate2 ../build_release_hfiemulate2_nouvwasi
	cd ../build_release_guardpages && make -j$(PARALLEL_COUNT)
	cd ../build_release_boundschecks && make -j$(PARALLEL_COUNT)
	cd ../build_release_masking && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfi && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfiemulate && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfiemulate_rr && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfiemulate2 && make -j$(PARALLEL_COUNT)
	cd ../build_release_hfiemulate2_nouvwasi && make -j$(PARALLEL_COUNT)

build_debug: ../build_debug_guardpages ../build_debug_boundschecks ../build_debug_masking ../build_debug_hfi ../build_debug_hfiemulate ../build_debug_hfiemulate_rr ../build_debug_hfiemulate2 ../build_debug_hfiemulate2_nouvwasi
	cd ../build_debug_guardpages && make -j$(PARALLEL_COUNT)
	cd ../build_debug_boundschecks && make -j$(PARALLEL_COUNT)
	cd ../build_debug_masking && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfi && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfiemulate && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfiemulate_rr && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfiemulate2 && make -j$(PARALLEL_COUNT)
	cd ../build_debug_hfiemulate2_nouvwasi && make -j$(PARALLEL_COUNT)

clean:
	rm -rf ../build_debug_*
	rm -rf ../build_release_*
