# UEFI modules analysing with BinDiff IDA plugin

## Table of Contents

- [Introduction](#introduction)
- [Software](#software)
- [Usage](#usage)
  - [i64 files generation](#i64-files-generation)
  - [Analysing release versions of UEFI images with BinDiff IDA plugin](#analysing-release-versions-of-uefi-images-with-bindiff-ida-plugin)
- [Conclusion](#conclusion)

# Introduction

In fact, most real UEFI firmwares are building using [edk2](https://github.com/tianocore/edk2). Thus, to simplify the analysis, we can match debug versions of UEFI images with release versions from real firmware using [BinDiff](https://www.zynamics.com/bindiff.html).

# Software

* [IDA Pro](https://www.hex-rays.com/products/ida/)
* [BinDiff](https://www.zynamics.com/bindiff.html) with IDA Pro plugin

# Usage

## i64 files generation

* clone this repo and update submodules

    ```bash
    git clone https://github.com/yeggor/UEFI_BinDiff
    cd UEFI_BinDiff
    git submodule update --init --recursive
    ```

* copy `analyse_and_exit.py` script to `idc` IDA directory (for example: `C:\Program Files\IDA Pro 7.5\idc`)
* check values in `config.json` file
* build efi modules with debug information

    * open Developer Command Prompt for VS
    * run `python edk2_build.py` from `UEFI_BinDiff` directory
    * if everything went well, you should see the `efi_modules` directory with `.efi` files
    * otherwise, you need to look for the reason [here](https://github.com/tianocore/tianocore.github.io/wiki/Getting-Started-with-EDK-II)

* run `python gen_idbs.py efi_modules` script to generate `i64` files

    * after the script end, you should see the IDA database files next to each `.efi` file

## Analysing release versions of UEFI images with BinDiff IDA plugin

Check [here](https://www.zynamics.com/bindiff/manual/index.html#N20676) to get started with `BinDiff IDA plugin`.

If the plugin is installed:

* open UEFI module in IDA
* `File` - `BinDiff`

    * choose `.efi.i64` file with similar name from `efi_modules` directory 
    * for example, for `DxeCore` file choose `efi_modules\DxeCore.i64` file

* you can import symbols and comments in `Matched Functions` window

    ![matched-functions](https://raw.githubusercontent.com/yeggor/UEFI_BinDiff/master/img/matched-functions.png)

* also you can compare the flow of execution for each function

    ![flow-graph](https://raw.githubusercontent.com/yeggor/UEFI_BinDiff/master/img/flow-graph.png)

# Conclusion

Using this method, you can significantly reduce the time for analysing UEFI images.
