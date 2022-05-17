# osed-tools
Tools/scripts I used/developed during the EXP-301 course.

# filter-ropfile.py
Tool to filter the rp++ output file for higher-quality ROP gadgets to greatly speed up the process of developing a ROP chain.
example without ASLR:
```
python3 filter-ropfile.py rpppfile.txt --bad-bytes "\x00\x0a\x0d"
```

With ASLR, specify the number of hex chars of the address to disregard and the imagebase rp++ used:
```
python3 filter-ropfile.py rpppfile.txt --bad-bytes "\x00\x0a\x0d" --aslr 4 --image-base 10000000
```

# dark-green-x64.wew
Adapted version of the workspace from https://github.com/nextco/windbg-readable-theme to be more compatible with the Exp-301 course. Credits go to Nextco for developing the theme! 

Edits made:
* Symbols are only resolved locally, as this otherwise hangs the UI for a while when starting WinDbg and attaching to a target process;
* Removed some unused windows. The Workspace now displays the assembly code & command windows like in the course and additionally also an overview of the registers and stack on the right. This greatly improved my work speed and visibility.

