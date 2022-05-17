# osed-tools
Tools/scripts I used/developed during the EXP-301 course.

# filter-ropfile.py
Tool to filter the rp++ output file for higher-quality ROP gadgets to greatly speed up the process of developing a ROP chain.
example without ASLR:
```
python3 filter-ropfile.py rpppfile.txt --bad-bytes "\x00\x0a\x0d"
```

parser = argparse.ArgumentParser(description='Filter rp++ output for high-quality gadgets')
    parser.add_argument('srcfile',type=str, help='rp++ output file to ingest')
    parser.add_argument('--bad-bytes', type=str, help='string of bad characters, formatted as \"\\x00\\x0a\" or \"000a\"')
    parser.add_argument('--aslr', type=int, help='Specify the number of hex characters to disregard for bad bytes in case ASLR is used. Will also convert addresses to format similar to dllbase+0x0000 in q1 and q2 outputs.')
    parser.add_argument('--dll-name', type=str, help='change the name from dllbase to something else. Useful in case gadgets from multiple dlls are used.')
    parser.add_argument('--image-base', type=str, help='dllbase used in rp++. Can be calculated with find-imagebase.py. Use in combination with --aslr flag for accurate gadget offsets, ready to copy.')


With ASLR, specify the number of bad chars to disregard and the imagebase rp++ used:
```
python3 filter-ropfile.py rpppfile.txt --bad-bytes "\x00\x0a\x0d" --aslr 4 --image-base 10000000
```

# dark-green-x64.wew
Adapted version of the workspace from https://github.com/nextco/windbg-readable-theme to be more compatible with the Exp-301 course. Credits go to Nextco for developing the theme! 

Edits made:
* Symbols are only resolved locally, as this otherwise hangs the UI for a while when starting WinDbg and attaching to a target process;
* Removed some unused windows. The Workspace now displays the assembly code & command windows like in the course and additionally also an overview of the registers and stack on the right. This greatly improved my work speed and visibility.

