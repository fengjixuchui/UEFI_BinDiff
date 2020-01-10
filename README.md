# UEFI Modules Analysing with BinDiff IDA plugin

## Table of Contents

1. [Introduction](#intro)
2. [Additional software](#soft)
3. [Usage](#usage)
4. [Conclusion](#conclusion)

## [Introduction](#intro)

In fact, most real UEFI firmwares are building using [edk2](https://github.com/tianocore/edk2). Thus, to simplify the analysis, we can match debug versions of UEFI images with release versions from real firmware using [BinDiff](https://www.zynamics.com/bindiff.html).

`debug-efi-elf-modules` directory contains some UEFI images with debugging information that were obtained when building `MdeModulePkg` and `OvmfPkg` packages from [edk2](https://github.com/tianocore/edk2).

## [Additional software](#soft)

* [IDA Pro](https://www.hex-rays.com/products/ida/)
* [BinDiff](https://www.zynamics.com/bindiff.html) with IDA Pro plugin

## [Usage](#usage)

### idb and i64 files generation

* extract `debug-efi-elf-modules` directory from `debug-efi-elf-modules.7z` archive
* copy `analyse_and_exit.py` script to `idc` IDA directory (for example: `C:\Program Files\IDA Pro 7.4\idc`)
* check values in `config.json` file
* run the `gen_idbs.py` script to generate `idb` and `i64` files
    - after the script runs, you should see the IDA database files next to each `.debug` file

### Analysing release versions of UEFI images with BinDiff IDA plugin

Check [here](https://www.zynamics.com/bindiff/manual/index.html#N20676) to get started with `BinDiff IDA plugin`.

If the plugin is installed:

* open UEFI module in IDA
* `File` - `BinDiff`
    * choose `.debug.idb` or `.debug.i64` file with similar name from `debug-efi-elf-modules` directory 
    * for example, for `DxeCore` `X64` file choose `debug-efi-elf-modules\X64\MdeModule\DxeCore.debug.i64` or `debug-efi-elf-modules\X64\Ovmf\DxeCore.debug.i64` file
* you can import symbols and comments in `Matched Functions` window

    ![matched-functions](https://raw.githubusercontent.com/yeggor/UEFI_BinDiff/master/img/matched-functions.png)

* also you can compare the flow of execution for each function

    ![flow-graph](https://raw.githubusercontent.com/yeggor/UEFI_BinDiff/master/img/flow-graph.png)

## [Conclusion](#conclusion)

Using this method, you can significantly reduce the time for analysing UEFI images.
